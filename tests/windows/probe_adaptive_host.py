"""Read-only host evidence. Never creates Jobs or changes process settings."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import platform


def observe():
    kernel = c.WinDLL("kernel32", use_last_error=True)
    advapi = c.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.GetCurrentProcess.argtypes = []
    kernel.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
    kernel.IsProcessInJob.restype = w.BOOL
    kernel.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
    kernel.GetProcessTimes.restype = w.BOOL
    kernel.ProcessIdToSessionId.argtypes = [w.DWORD, c.POINTER(w.DWORD)]
    kernel.ProcessIdToSessionId.restype = w.BOOL
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.CloseHandle.restype = w.BOOL
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    advapi.OpenProcessToken.restype = w.BOOL
    advapi.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
    advapi.GetTokenInformation.restype = w.BOOL
    process = kernel.GetCurrentProcess()
    in_job, session = w.BOOL(), w.DWORD()
    created, exited, system, user = (w.FILETIME() for _ in range(4))
    result = {"schema_version": 1, "pid": os.getpid(), "parent_pid": os.getppid(),
              "platform": platform.platform(), "python": platform.python_version(),
              "python_bitness": c.sizeof(c.c_void_p) * 8,
              "in_any_job": None, "session_id": None, "creation_filetime": None,
              "authentication_luid": None, "validity": "unknown", "errors": []}

    def failed(stage):
        result["errors"].append({"stage": stage, "win32_error": c.get_last_error()})

    if not kernel.IsProcessInJob(process, None, c.byref(in_job)):
        failed("IsProcessInJob")
    else:
        result["in_any_job"] = bool(in_job.value)
    if not kernel.GetProcessTimes(process, c.byref(created), c.byref(exited), c.byref(system), c.byref(user)):
        failed("GetProcessTimes")
    else:
        result["creation_filetime"] = str((created.dwHighDateTime << 32) | created.dwLowDateTime)
    if not kernel.ProcessIdToSessionId(os.getpid(), c.byref(session)):
        failed("ProcessIdToSessionId")
    else:
        result["session_id"] = session.value
    token = w.HANDLE()
    if not advapi.OpenProcessToken(process, 8, c.byref(token)):
        failed("OpenProcessToken")
    else:
        try:
            needed = w.DWORD()
            sized = advapi.GetTokenInformation(token, 10, None, 0, c.byref(needed))  # TokenStatistics
            if sized or c.get_last_error() != 122 or not 16 <= needed.value <= 4096:
                failed("GetTokenInformationSize")
            else:
                buffer = c.create_string_buffer(needed.value)
                if not advapi.GetTokenInformation(token, 10, buffer, len(buffer), c.byref(needed)):
                    failed("GetTokenInformation")
                else:
                    # TOKEN_STATISTICS starts with TokenId LUID, then AuthenticationId.
                    result["authentication_luid"] = buffer.raw[8:16].hex()
        finally:
            if not kernel.CloseHandle(token):
                failed("CloseHandle(token)")
    result["validity"] = "valid" if not result["errors"] else "unknown"
    result["active_host_candidate"] = result["validity"] == "valid" and result["in_any_job"] is False
    result["capability_status"] = "host_only_not_control_verified" if not result["errors"] else "host_observation_unknown"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("Windows host probe only; no capability verified")
    # A fresh name is required; no existing evidence or user file is overwritten.
    options.output = options.output.resolve()
    if ".resource-sentinel" in (part.casefold() for part in options.output.parts):
        raise SystemExit("Production data directory is not an isolated probe output")
    if options.output.exists():
        raise SystemExit("Output evidence already exists")
    observation = observe()
    pending = options.output.with_name(options.output.name + ".pending")
    with pending.open("x", encoding="utf-8") as output:
        json.dump(observation, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    pending.rename(options.output)
    raise SystemExit(0 if observation["validity"] == "valid" else 2)
