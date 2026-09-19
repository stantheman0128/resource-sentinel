"""One bounded test-only Explorer dispatch of a fixed read-only self probe.

This is not a production launcher or a fallback for managed commands. It never
uses parent spoofing, breakaway, Job creation, elevated verbs or process writes.
The native preflight must first identify a same-logon, normal desktop Explorer.
Explorer COM automation follows Microsoft's 2013 desktop folder-view route.
An uncertain dispatch is recorded once, never retried or killed. The child has
a shared 15-second ticket deadline and at most 10 seconds waiting for an ACK.
ACK proves only independent observation of this test child. In-Job children can
complete diagnostics, but remain unsupported control hosts and never candidates.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import importlib.util
import json
import math
import ntpath
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import threading
import time


_SPEC = importlib.util.spec_from_file_location("desktop_preflight", Path(__file__).with_name("probe_adaptive_desktop.py"))
preflight = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(preflight)
CHILD = Path(__file__).resolve().parents[1] / "fixtures" / "adaptive_desktop_probe_child.py"
TIME_LIMIT = 15.0
ACK_LIMIT = 10.0
MAX_JSON_BYTES = 16384


class ProbeError(Exception):
    pass


def _reject_constant(value):
    raise ProbeError("nonfinite_json")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ProbeError("nonfinite_json")
    return number


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProbeError("duplicate_json_key")
        value[key] = item
    return value


def read_json(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ProbeError("symlink_evidence_forbidden")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProbeError("evidence_identity_changed")
        raw = stream.read(MAX_JSON_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ProbeError("evidence_changed_during_read")
    if len(raw) > MAX_JSON_BYTES:
        raise ProbeError("evidence_too_large")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=_reject_constant, parse_float=_finite_float)
    if not isinstance(value, dict):
        raise ProbeError("evidence_not_object")
    return value


def write_new_json(path, value):
    """Publish only a new file in the private nonce directory, on Windows."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ProbeError("evidence_already_exists")
    pending = path.with_name(path.name + ".pending")
    with pending.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, allow_nan=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    # Windows rename fails if the destination already exists. Keep failed
    # pending evidence; never replace an earlier report or retry a dispatch.
    pending.rename(path)


def same_image(actual, expected):
    return ntpath.normcase(ntpath.normpath(actual)) == ntpath.normcase(ntpath.normpath(expected))


def local_output_root(value):
    root = Path(value)
    if os.fspath(value).replace("\\", "/").startswith("//") or not root.is_absolute() or ".." in root.parts:
        raise ProbeError("local_absolute_output_required")
    # This experiment owns only the implementation worktree's ignored evidence
    # tree. No network root, production data directory, junction or other tree.
    owned = Path(__file__).resolve().parents[2] / ".local-adaptive"
    if not root.is_relative_to(owned):
        raise ProbeError("isolated_worktree_output_required")
    for component in (root, *root.parents):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or component.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ProbeError("redirected_output_directory")
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.GetDriveTypeW.argtypes, kernel.GetDriveTypeW.restype = [w.LPCWSTR], w.UINT
    if kernel.GetDriveTypeW(root.anchor) != 3:  # DRIVE_FIXED only
        raise ProbeError("fixed_local_storage_required")
    return root.resolve(strict=True)


def assert_desktop_identity(caller, desktop, expected_image):
    if not same_image(desktop["image_path"], expected_image):
        raise ProbeError("unexpected_desktop_image")
    for field in ("user_sid", "logon_sid", "authentication_luid", "session_id"):
        if caller[field] != desktop[field]:
            raise ProbeError("desktop_identity_mismatch")
    for process in (caller, desktop):
        if process["elevated"] is not False or process["integrity_rid"] != 0x2000:
            raise ProbeError("desktop_or_caller_not_normal_integrity")
    if desktop["in_any_job"] is not False:
        raise ProbeError("desktop_foreign_job")


def fixed_launch(python, run_directory, nonce):
    """No command, executable or workload PID is accepted from the CLI."""
    python = Path(python).resolve(strict=True)
    if python.name.casefold() != "python.exe":
        raise ProbeError("unsupported_python_launcher")
    executable = python.with_name("pythonw.exe")
    if not executable.is_file() or executable.is_symlink() or not CHILD.is_file():
        raise ProbeError("fixed_probe_executable_unavailable")
    # The Windows CRT quoting function only serializes these fixed arguments;
    # cmd.exe and other shells are never involved.
    arguments = subprocess.list2cmdline([
        "-I", str(CHILD), "--run-directory", str(run_directory), "--nonce", nonce,
    ])
    return str(executable), arguments


def _dispatch_call(dispatch, name, flags, *arguments):
    member = dispatch.GetIDsOfNames(name)
    return dispatch.Invoke(member, 0, flags, True, *arguments)


class DesktopAutomation:
    """COM interfaces live and are released in their creating STA thread."""

    def __init__(self, api, expected_hwnd, expected_pid):
        import pythoncom
        from win32com.client import VARIANT
        from win32com.shell import shell, shellcon

        self.pythoncom = pythoncom
        self.references = []
        self.application = None
        self.initialized = False
        pythoncom.CoInitializeEx(pythoncom.COINIT_APARTMENTTHREADED)
        self.initialized = True
        try:
            windows = pythoncom.CoCreateInstance(
                pythoncom.MakeIID("{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"),
                None, pythoncom.CLSCTX_ALL, pythoncom.IID_IDispatch,
            )
            self.references.append(windows)
            hwnd = VARIANT(pythoncom.VT_BYREF | pythoncom.VT_I4, 0)
            found = _dispatch_call(windows, "FindWindowSW", pythoncom.DISPATCH_METHOD,
                                   VARIANT(pythoncom.VT_I4, 0), VARIANT(pythoncom.VT_EMPTY, None),
                                   8, hwnd, 1)  # CSIDL_DESKTOP, SWC_DESKTOP, SWFO_NEEDDISPATCH
            if found is None or (int(hwnd.value) & 0xFFFFFFFF) != (int(expected_hwnd) & 0xFFFFFFFF):
                raise ProbeError("desktop_com_window_mismatch")
            self.references.append(found)
            provider = found.QueryInterface(pythoncom.IID_IServiceProvider)
            browser = provider.QueryService(shell.SID_STopLevelBrowser, shell.IID_IShellBrowser)
            view = browser.QueryActiveShellView()
            self.references.extend((provider, browser, view))
            view_hwnd = view.GetWindow()
            view_pid = w.DWORD()
            if not api.user.GetWindowThreadProcessId(view_hwnd, c.byref(view_pid)) or view_pid.value != expected_pid:
                raise ProbeError("desktop_com_view_owner_mismatch")
            background = view.GetItemObject(shellcon.SVGIO_BACKGROUND, pythoncom.IID_IDispatch)
            self.references.append(background)
            # Application is obtained from the actual desktop folder view. A
            # newly created generic Shell.Application is never used to launch.
            application = _dispatch_call(background, "Application", pythoncom.DISPATCH_PROPERTYGET)
            # pywin32 need not have a native IShellDispatch2 wrapper. Verify
            # that interface as IUnknown (the safe common COM base), then ask
            # COM for IDispatch. Never reinterpret an unknown interface vtable.
            verified = application.QueryInterface(
                pythoncom.MakeIID("{A4C6892C-3BA9-11D2-9DEA-00C04FB16162}"), pythoncom.IID_IUnknown)
            self.application = verified.QueryInterface(pythoncom.IID_IDispatch)
            self.references.extend((application, verified, self.application))
        except Exception:
            # Release local interface references before apartment teardown too.
            windows = found = provider = browser = view = background = application = verified = None
            self.close()
            raise

    def dispatch_fixed_probe(self, executable, arguments, directory):
        _dispatch_call(self.application, "ShellExecute", self.pythoncom.DISPATCH_METHOD,
                       executable, arguments, directory, "open", 0)

    def close(self):
        self.application = None
        self.references.clear()
        if self.initialized:
            self.pythoncom.CoUninitialize()
            self.initialized = False


def _safe_error(error):
    if isinstance(error, ProbeError):
        return {"stage": str(error)}  # ProbeError messages above are fixed reason codes.
    if isinstance(error, preflight.ObservationError):
        return preflight._public_error(error)
    result = {"stage": "unexpected_probe_error", "error_type": type(error).__name__}
    if isinstance(getattr(error, "hresult", None), int):
        result["hresult"] = error.hresult
    return result


def dispatch_worker(state, complete, executable, arguments, run_directory, deadline):
    handles, automation, api = [], None, None
    try:
        api = preflight.NativeReadOnly()
        desktop_binding = api.desktop()
        caller_pid, desktop_pid = os.getpid(), desktop_binding[1]
        caller_handle = api.open_process(caller_pid)
        handles.append(caller_handle)
        desktop_handle = api.open_process(desktop_pid)
        handles.append(desktop_handle)
        caller = api.read_process(caller_handle, caller_pid)
        desktop = api.read_process(desktop_handle, desktop_pid)
        assert_desktop_identity(caller, desktop, api.expected_explorer())
        if not same_image(caller["image_path"], sys.executable):
            raise ProbeError("caller_interpreter_image_mismatch")
        automation = DesktopAutomation(api, *desktop_binding)
        # Verify native handles and actual desktop ownership immediately before
        # the sole dispatch. Old saved preflight evidence never authorizes it.
        if caller != api.read_process(caller_handle, caller_pid) or desktop != api.read_process(desktop_handle, desktop_pid):
            raise ProbeError("identity_changed_before_dispatch")
        if desktop_binding != api.desktop():
            raise ProbeError("desktop_changed_before_dispatch")
        if time.monotonic() >= deadline - ACK_LIMIT:
            raise ProbeError("dispatch_preflight_deadline")
        if state["stop_dispatch"].is_set():
            raise ProbeError("controller_stopped_before_dispatch")
        state["identity"] = {"caller": caller, "desktop": desktop, "binding": desktop_binding}
        state["dispatch_attempted"] = True
        automation.dispatch_fixed_probe(executable, arguments, str(run_directory))
        state["com_returned_successfully"] = True
    except Exception as error:
        state.setdefault("errors", []).append(_safe_error(error))
    finally:
        if automation is not None:
            try:
                automation.close()
            except Exception as error:
                state.setdefault("errors", []).append(_safe_error(error))
        for handle in reversed(handles):
            try:
                api.close(handle)
            except Exception as error:
                state.setdefault("errors", []).append(_safe_error(error))
        complete.set()


def validate_ready(ready, nonce):
    if set(ready) != {"schema_version", "nonce", "process"} or type(ready.get("schema_version")) is not int or ready.get("schema_version") != 1 or ready.get("nonce") != nonce:
        raise ProbeError("ready_protocol_mismatch")
    process = ready.get("process")
    if not isinstance(process, dict) or type(process.get("pid")) is not int or process["pid"] <= 0:
        raise ProbeError("ready_process_identity_invalid")
    birth = process.get("creation_filetime")
    if not isinstance(birth, str) or not birth.isascii() or not birth.isdecimal() or not 0 < int(birth) < 2**64:
        raise ProbeError("ready_birth_invalid")
    if set(process) != {"pid", "creation_filetime", "session_id", "in_any_job", "elevated", "integrity_rid"}:
        raise ProbeError("ready_process_schema_invalid")
    if any(type(process.get(field)) is not bool for field in ("in_any_job", "elevated")) or any(
            type(process.get(field)) is not int or process[field] < 0 for field in ("session_id", "integrity_rid")):
        raise ProbeError("ready_process_types_invalid")
    return process


def verify_child(api, ready, nonce, context, executable):
    published = validate_ready(ready, nonce)
    handle = api.open_process(published["pid"])
    try:
        child = api.read_process(handle, published["pid"])
        if preflight._public_process(child) != published:
            raise ProbeError("child_self_identity_mismatch")
        if not same_image(child["image_path"], executable):
            raise ProbeError("child_executable_mismatch")
        if int(child["creation_filetime"]) <= int(context["caller"]["creation_filetime"]):
            raise ProbeError("child_not_new_for_this_probe")
        # Do not reuse assert_desktop_identity: Explorer must remain outside a
        # Job, whereas a diagnostic child inside a Job still has observable
        # exact identity. Observation never authorizes managed enrollment.
        for field in ("user_sid", "logon_sid", "authentication_luid", "session_id"):
            if child[field] != context["caller"][field]:
                raise ProbeError("child_identity_mismatch")
        if child["elevated"] is not False or child["integrity_rid"] != 0x2000:
            raise ProbeError("child_not_normal_integrity")
        if child != api.read_process(handle, published["pid"]):
            raise ProbeError("child_identity_changed")
        # Parent also independently reopens and verifies the desktop identity
        # before ACK. No reliance on the COM thread's status or child claims.
        desktop_handle = api.open_process(context["desktop"]["pid"])
        try:
            if api.read_process(desktop_handle, context["desktop"]["pid"]) != context["desktop"] or api.desktop() != context["binding"]:
                raise ProbeError("desktop_changed_before_ack")
        finally:
            api.close(desktop_handle)
        return handle, child
    except Exception:
        api.close(handle)
        raise


def child_exit_code(api, handle):
    status = api.kernel.WaitForSingleObject(handle, 0)
    if status == 258:
        return None
    if status != 0:
        raise ProbeError("child_exit_wait_unknown")
    api.kernel.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    api.kernel.GetExitCodeProcess.restype = w.BOOL
    code = w.DWORD()
    if not api.kernel.GetExitCodeProcess(handle, c.byref(code)):
        api._failed("GetExitCodeProcess")
    return int(code.value)


def sanitized_child_diagnostics(value, child):
    specification = importlib.util.spec_from_file_location(
        "adaptive_parent_diagnostics", Path(__file__).with_name("adaptive_job_diagnostics.py"))
    if specification is None or specification.loader is None:
        raise ProbeError("diagnostics_import_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    try:
        result = module.sanitize_diagnostics(value)
        if result["self"] != preflight._public_process(child):
            raise ValueError("identity mismatch")
        return result
    except Exception:
        raise ProbeError("child_diagnostics_invalid") from None


def completion_verified(done, nonce, child, exit_code):
    required = {"schema_version", "nonce", "outcome", "errors", "process"}
    matches = (required.issubset(done) and set(done).issubset(required | {"diagnostics"})
            and type(exit_code) is int and exit_code == 0 and type(done.get("schema_version")) is int
            and done.get("schema_version") == 1 and done.get("nonce") == nonce and done.get("errors") == []
            and done.get("outcome") == "acknowledged" and done.get("process") == preflight._public_process(child))
    if matches and "diagnostics" in done:
        try:
            sanitized_child_diagnostics(done["diagnostics"], child)
        except Exception:
            return False
    return matches


def finish_observation(report, child, *, complete, com_success, dispatch_attempted, worker_errors):
    report["observation_completed"] = bool(complete and com_success and report["child_verified"]
                                           and report["child_exit_verified"]
                                           and not worker_errors and not report["errors"])
    # In particular, an immediate Job with CPU flags == 0 says nothing about
    # its ancestors. Only native held-child membership can pass this narrow
    # host-candidate predicate; neither handshake nor diagnostics override it.
    report["candidate"] = bool(report["observation_completed"] and child is not None
                               and child["in_any_job"] is False)
    report["control_eligible"] = False  # no CPU/control capability was tested
    report["control_status"] = ("unsupported_foreign_or_unknown_job" if child is not None
                                and child["in_any_job"] is True else "not_control_verified")
    if report["candidate"]:
        report["result"] = "candidate_independent_host_not_control_verified"
    elif report["observation_completed"]:
        report["result"] = "observation_complete_control_unsupported"
    else:
        report["result"] = "launch_outcome_unknown" if dispatch_attempted else "desktop_preflight_blocked"


def summarize_unverified_child_report(done, nonce):
    """Diagnostics only: no READY/held handle means self-reports prove no gate."""
    required = {"schema_version", "nonce", "outcome", "errors"}
    if not required.issubset(done) or not set(done).issubset(required | {"process", "diagnostics"}) or type(done.get("schema_version")) is not int or done["schema_version"] != 1 or done["nonce"] != nonce:
        raise ProbeError("unverified_done_protocol_mismatch")
    outcomes = {"acknowledged", "ack_timeout", "observation_unknown", "ticket_expired"}
    if done["outcome"] not in outcomes or not isinstance(done["errors"], list):
        raise ProbeError("unverified_done_fields_invalid")
    result = {"verification": "child_self_report_unverified", "outcome": done["outcome"],
              "identity_verified": False, "exit_verified": False, "reported_errors": [],
              "reported_error_count": len(done["errors"])}
    if "process" in done:
        result["process"] = validate_ready({"schema_version": 1, "nonce": nonce, "process": done["process"]}, nonce)
    if "diagnostics" in done:
        if "process" not in result:
            raise ProbeError("unverified_done_fields_invalid")
        result["diagnostics"] = sanitized_child_diagnostics(done["diagnostics"], result["process"])
    allowed_reasons = {"unsupported_self_identity", "self_identity_changed", "ticket_expired", "ack_invalid",
                       "self_observation_failed", "unexpected_probe_error", "run_directory_already_used",
                       "output_already_exists"}
    for error in done["errors"][:8]:
        if not isinstance(error, dict):
            raise ProbeError("unverified_done_error_invalid")
        stage = error.get("stage")
        item = {"stage": stage if isinstance(stage, str) and stage in allowed_reasons else "unrecognized_child_reason"}
        code = error.get("win32_error")
        if type(code) is int and 0 <= code <= 0xFFFFFFFF:
            item["win32_error"] = code
        result["reported_errors"].append(item)
    return result


def add_unverified_child_diagnostic(report, run_directory, nonce):
    # A child can reject its own host before publishing READY. Preserve that
    # useful bounded diagnostic without treating a done file as native proof.
    if not report.get("child_verified") and (run_directory / "done.json").exists():
        try:
            report["child_self_report_unverified"] = summarize_unverified_child_report(
                read_json(run_directory / "done.json"), nonce)
        except Exception as error:
            report["errors"].append(_safe_error(error))


def run_probe(output_directory):
    root = local_output_root(output_directory)
    nonce = secrets.token_hex(16)
    run_directory = root / nonce
    run_directory.mkdir()  # collision is an error, never reuse earlier evidence
    report = dict(schema_version=1, nonce=nonce, result="not_started", candidate=False,
                  observation_completed=False, control_eligible=False, control_status="not_control_verified",
                  dispatch_attempted=False, com_returned_successfully=False,
                  child_verified=False, child_exit_verified=False, process_control_writes=0,
                  production_tasks_changed=0, retries=0, capability_status="host_only_not_control_verified", errors=[])
    state, complete, child_handle, api = {"errors": [], "stop_dispatch": threading.Event()}, threading.Event(), None, None
    thread = None
    try:
        if os.name != "nt":
            raise ProbeError("windows_only")
        executable, arguments = fixed_launch(sys.executable, run_directory, nonce)
        now = time.monotonic()
        deadline = now + TIME_LIMIT
        write_new_json(run_directory / "request.json", dict(schema_version=1, nonce=nonce,
                       issued_monotonic=now, deadline_monotonic=deadline, expected_python_basename="pythonw.exe"))
        thread = threading.Thread(target=dispatch_worker,
                                  args=(state, complete, executable, arguments, run_directory, deadline), daemon=True)
        thread.start()
        api = preflight.NativeReadOnly()
        attempted_verification = False
        child, exit_code = None, None
        while time.monotonic() < deadline:
            ready_path = run_directory / "ready.json"
            if not attempted_verification and ready_path.exists():
                attempted_verification = True
                if not state.get("dispatch_attempted") or "identity" not in state:
                    raise ProbeError("unexpected_child_evidence_before_dispatch")
                ready = read_json(ready_path)
                child_handle, child = verify_child(api, ready, nonce, state["identity"], executable)
                report["child_verified"] = True
                report["child"] = preflight._public_process(child)
                write_new_json(run_directory / "ack.json", {"schema_version": 1, "nonce": nonce, "accepted": True})
            if child_handle is not None:
                exit_code = child_exit_code(api, child_handle)
                if exit_code is not None and complete.is_set():
                    break
            if complete.is_set() and not state.get("dispatch_attempted"):
                break
            time.sleep(0.025)
        report["com_thread_completed"] = complete.is_set()
        if not complete.is_set():
            report["errors"].append({"stage": "com_dispatch_or_cleanup_deadline"})
        if child is not None and exit_code is not None:
            report["child_exit_code"] = exit_code
            done_path = run_directory / "done.json"
            if done_path.exists():
                done = read_json(done_path)
                report["child_exit_verified"] = completion_verified(done, nonce, child, exit_code)
                if report["child_exit_verified"] and "diagnostics" in done:
                    report["child_diagnostics_self_report"] = sanitized_child_diagnostics(done["diagnostics"], child)
        finish_observation(report, child, complete=complete.is_set(),
                           com_success=bool(state.get("com_returned_successfully")),
                           dispatch_attempted=bool(state.get("dispatch_attempted")), worker_errors=state["errors"])
    except Exception as error:
        state["stop_dispatch"].set()
        report["errors"].append(_safe_error(error))
        report["result"] = "launch_outcome_unknown" if state.get("dispatch_attempted") or (thread is not None and not complete.is_set()) else "desktop_preflight_blocked"
    finally:
        if child_handle is not None:
            try:
                api.close(child_handle)
            except Exception as error:
                report["errors"].append(_safe_error(error))
        # Only a sanitized snapshot is exported. Raw token identifiers in the
        # daemon thread's private context never enter telemetry or JSON.
        report["dispatch_attempted"] = bool(state.get("dispatch_attempted"))
        report["com_returned_successfully"] = bool(state.get("com_returned_successfully"))
        report["errors"].extend(list(state["errors"]))
        if "identity" in state:
            report["desktop"] = preflight._public_process(state["identity"]["desktop"])
        add_unverified_child_diagnostic(report, run_directory, nonce)
        if report["errors"]:
            report["candidate"] = False
            report["observation_completed"] = False
            if report["result"] in ("candidate_independent_host_not_control_verified", "observation_complete_control_unsupported"):
                report["result"] = "completion_or_cleanup_unknown"
        write_new_json(run_directory / "result.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", required=True, type=Path)
    parser.add_argument("--dispatch-read-only-probe", action="store_true")
    options = parser.parse_args(argv)
    if not options.dispatch_read_only_probe:
        parser.error("Explicit --dispatch-read-only-probe is required")
    result = run_probe(options.output_directory)
    print(json.dumps(result, indent=2))
    return 0 if result["candidate"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
