"""Read-only P1 desktop host preflight; never dispatches or controls processes.

Only the current process and GetShellWindow's actual owner may be inspected.
A successful result is permission to investigate a candidate, not launch/control
capability evidence. Execute through normal host admission. No spike opt-in or
production module is imported, and no raw token identifiers leave memory.
"""
from __future__ import annotations

import argparse
import ctypes as c
from ctypes import wintypes as w
import json
import ntpath
import os
from pathlib import Path
import platform
import struct


class ObservationError(Exception):
    def __init__(self, stage: str, win32_error: int | None = None):
        super().__init__(stage)
        self.stage = stage
        self.win32_error = win32_error


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [("Sid", c.c_void_p), ("Attributes", w.DWORD)]


class TOKEN_GROUPS_ONE(c.Structure):
    _fields_ = [("GroupCount", w.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1)]


def _sid_from_buffer(buffer, pointer: int) -> str:
    """Decode only bounded SID bytes inside an OS-owned token result buffer."""
    start = int(pointer or 0) - c.addressof(buffer)
    raw = buffer.raw
    if start < 0 or start + 8 > len(raw):
        raise ObservationError("token_sid_pointer_invalid")
    revision, count = raw[start], raw[start + 1]
    if revision != 1 or count > 15 or start + 8 + count * 4 > len(raw):
        raise ObservationError("token_sid_size_invalid")
    authority = int.from_bytes(raw[start + 2:start + 8], "big")
    sub = struct.unpack_from("<" + "I" * count, raw, start + 8)
    return "S-1-" + str(authority) + "".join("-" + str(value) for value in sub)


class NativeReadOnly:
    """All process handles are QUERY_LIMITED_INFORMATION | SYNCHRONIZE only."""

    def __init__(self):
        if os.name != "nt" or c.sizeof(c.c_void_p) != 8:
            raise ObservationError("unsupported_platform_or_bitness")
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.user = c.WinDLL("user32", use_last_error=True)
        self.advapi = c.WinDLL("advapi32", use_last_error=True)
        signatures = (
            (self.kernel, "OpenProcess", [w.DWORD, w.BOOL, w.DWORD], w.HANDLE),
            (self.kernel, "CloseHandle", [w.HANDLE], w.BOOL),
            (self.kernel, "GetProcessId", [w.HANDLE], w.DWORD),
            (self.kernel, "GetProcessTimes", [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4, w.BOOL),
            (self.kernel, "QueryFullProcessImageNameW", [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)], w.BOOL),
            (self.kernel, "ProcessIdToSessionId", [w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
            (self.kernel, "IsProcessInJob", [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL),
            (self.kernel, "WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD),
            (self.kernel, "GetWindowsDirectoryW", [w.LPWSTR, w.UINT], w.UINT),
            (self.user, "GetShellWindow", [], w.HWND),
            (self.user, "GetWindowThreadProcessId", [w.HWND, c.POINTER(w.DWORD)], w.DWORD),
            (self.advapi, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL),
            (self.advapi, "GetTokenInformation", [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)], w.BOOL),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def _failed(stage):
        raise ObservationError(stage, c.get_last_error())

    def desktop(self):
        hwnd = self.user.GetShellWindow()
        if not hwnd:
            raise ObservationError("desktop_window_unavailable")
        pid = w.DWORD()
        if not self.user.GetWindowThreadProcessId(hwnd, c.byref(pid)) or not pid.value:
            self._failed("GetWindowThreadProcessId")
        return int(hwnd), int(pid.value)

    def expected_explorer(self):
        buffer = c.create_unicode_buffer(32768)
        length = self.kernel.GetWindowsDirectoryW(buffer, len(buffer))
        if not 0 < length < len(buffer):
            self._failed("GetWindowsDirectoryW")
        return ntpath.join(buffer.value, "explorer.exe")

    def open_process(self, pid):
        handle = self.kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        if not handle:
            self._failed("OpenProcess(query_sync)")
        return handle

    def close(self, handle):
        if not self.kernel.CloseHandle(handle):
            self._failed("CloseHandle")

    def _token(self, handle, information_class, minimum):
        needed = w.DWORD()
        # TokenSessionId is DWORD; TOKEN_ELEVATION contains one DWORD. Query
        # these documented fixed-size results directly. This host returns
        # ERROR_BAD_LENGTH for TokenElevation's NULL/0 size probe, so requiring
        # ERROR_INSUFFICIENT_BUFFER there incorrectly rejected a readable token.
        # A failed real query remains unknown; no error is treated as elevation=0.
        fixed_size = {12: 4, 20: 4}.get(information_class)
        if fixed_size is not None:
            if minimum != fixed_size:
                raise ObservationError("fixed_token_size_contract_invalid")
            buffer = c.create_string_buffer(fixed_size)
            if not self.advapi.GetTokenInformation(handle, information_class, buffer, fixed_size, c.byref(needed)):
                self._failed("GetTokenInformation_" + str(information_class))
            if needed.value != fixed_size:
                raise ObservationError("fixed_token_result_size_invalid")
            return buffer
        result = self.advapi.GetTokenInformation(handle, information_class, None, 0, c.byref(needed))
        if result or c.get_last_error() != 122 or not minimum <= needed.value <= 65536:
            self._failed("GetTokenInformationSize_" + str(information_class))
        buffer = c.create_string_buffer(needed.value)
        if not self.advapi.GetTokenInformation(handle, information_class, buffer, len(buffer), c.byref(needed)):
            self._failed("GetTokenInformation_" + str(information_class))
        # SID pointers must remain inside the original allocation. A token
        # changing between sizing and retrieval can produce a shorter result;
        # reject it rather than parsing unreturned bytes or copying pointers.
        if needed.value != len(buffer):
            raise ObservationError("token_result_size_changed")
        return buffer

    def _token_fields(self, process):
        token = w.HANDLE()
        if not self.advapi.OpenProcessToken(process, 8, c.byref(token)):  # TOKEN_QUERY only
            self._failed("OpenProcessToken(query)")
        try:
            user = self._token(token, 1, c.sizeof(SID_AND_ATTRIBUTES))
            user_sid = _sid_from_buffer(user, SID_AND_ATTRIBUTES.from_buffer(user).Sid)
            groups = self._token(token, 2, TOKEN_GROUPS_ONE.Groups.offset)
            count = struct.unpack_from("<I", groups.raw)[0]
            offset, size = TOKEN_GROUPS_ONE.Groups.offset, c.sizeof(SID_AND_ATTRIBUTES)
            if count > 4096 or offset + count * size > len(groups):
                raise ObservationError("token_groups_size_invalid")
            logon_sids = []
            for index in range(count):
                group = SID_AND_ATTRIBUTES.from_buffer(groups, offset + index * size)
                if group.Attributes & 0xC0000000 == 0xC0000000:  # SE_GROUP_LOGON_ID
                    logon_sids.append(_sid_from_buffer(groups, group.Sid))
            if len(logon_sids) != 1:
                raise ObservationError("token_logon_sid_ambiguous")
            statistics = self._token(token, 10, 16)
            auth = statistics.raw[8:16].hex()  # TOKEN_STATISTICS.AuthenticationId
            session = struct.unpack_from("<I", self._token(token, 12, 4).raw)[0]
            elevated = struct.unpack_from("<I", self._token(token, 20, 4).raw)[0]
            # TOKEN_ELEVATION defines every nonzero DWORD as elevated.
            label = self._token(token, 25, c.sizeof(SID_AND_ATTRIBUTES))
            integrity = _sid_from_buffer(label, SID_AND_ATTRIBUTES.from_buffer(label).Sid)
            components = integrity.split("-")
            if len(components) != 4 or components[:3] != ["S", "1", "16"]:
                raise ObservationError("token_integrity_invalid")
            return dict(user_sid=user_sid, logon_sid=logon_sids[0], authentication_luid=auth,
                        token_session_id=session, elevated=bool(elevated), integrity_rid=int(components[3]))
        finally:
            self.close(token)

    def read_process(self, handle, expected_pid):
        # A held handle, not another OpenProcess by PID, is used throughout.
        if self.kernel.WaitForSingleObject(handle, 0) != 258:  # WAIT_TIMEOUT: still alive
            raise ObservationError("process_not_verified_alive")
        if self.kernel.GetProcessId(handle) != expected_pid:
            raise ObservationError("process_id_mismatch")
        created, exited, system, user = (w.FILETIME() for _ in range(4))
        if not self.kernel.GetProcessTimes(handle, c.byref(created), c.byref(exited), c.byref(system), c.byref(user)):
            self._failed("GetProcessTimes")
        birth = (created.dwHighDateTime << 32) | created.dwLowDateTime
        if not birth:
            raise ObservationError("process_birth_invalid")
        image = c.create_unicode_buffer(32768)
        length = w.DWORD(len(image))
        if not self.kernel.QueryFullProcessImageNameW(handle, 0, image, c.byref(length)):
            self._failed("QueryFullProcessImageNameW")
        session, in_job = w.DWORD(), w.BOOL()
        if not self.kernel.ProcessIdToSessionId(expected_pid, c.byref(session)):
            self._failed("ProcessIdToSessionId")
        if not self.kernel.IsProcessInJob(handle, None, c.byref(in_job)):
            self._failed("IsProcessInJob")
        result = dict(pid=expected_pid, creation_filetime=str(birth), image_path=image.value,
                      session_id=int(session.value), in_any_job=bool(in_job.value), **self._token_fields(handle))
        if result["token_session_id"] != result["session_id"]:
            raise ObservationError("process_token_session_mismatch")
        if self.kernel.WaitForSingleObject(handle, 0) != 258:
            raise ObservationError("process_exited_during_observation")
        return result


def _public_process(observation):
    return {name: observation[name] for name in (
        "pid", "creation_filetime", "session_id", "in_any_job", "elevated", "integrity_rid")}


def observe(api=None):
    """Injectable query adapter for pure tests; no target PID option exists."""
    report = dict(schema_version=1, probe="desktop_read_only_preflight", platform=platform.platform(),
                  python_bitness=c.sizeof(c.c_void_p) * 8, validity="unknown", candidate=False,
                  result="observation_unknown", dispatches=0, process_control_writes=0,
                  capability_status="not_launch_or_control_verified", errors=[])
    handles = []
    try:
        api = NativeReadOnly() if api is None else api
        caller_pid = os.getpid()
        desktop_window, desktop_pid = api.desktop()
        expected_explorer = api.expected_explorer()
        caller_handle = api.open_process(caller_pid)
        handles.append(caller_handle)
        desktop_handle = api.open_process(desktop_pid)
        handles.append(desktop_handle)
        caller = api.read_process(caller_handle, caller_pid)
        desktop = api.read_process(desktop_handle, desktop_pid)
        # Full repeated observations catch token, membership and image changes as
        # well as process exits; the original handles remain open until finally.
        if caller != api.read_process(caller_handle, caller_pid):
            raise ObservationError("caller_identity_changed")
        if desktop != api.read_process(desktop_handle, desktop_pid):
            raise ObservationError("desktop_identity_changed")
        if (desktop_window, desktop_pid) != api.desktop():
            raise ObservationError("desktop_window_owner_changed")
        report["caller"] = _public_process(caller)
        report["desktop"] = _public_process(desktop)
        report["matches"] = {key: caller[key] == desktop[key] for key in (
            "user_sid", "logon_sid", "authentication_luid", "session_id")}
        report["expected_explorer_image"] = ntpath.normcase(ntpath.normpath(desktop["image_path"])) == ntpath.normcase(ntpath.normpath(expected_explorer))
        report["caller_host_supported"] = not caller["in_any_job"]
        report["validity"] = "valid"
        if not report["expected_explorer_image"]:
            report["result"] = "unsupported_desktop_image"
        elif not all(report["matches"].values()):
            report["result"] = "unsupported_user_logon_or_session"
        elif caller["elevated"] or desktop["elevated"]:
            report["result"] = "unsupported_elevated_process"
        elif caller["integrity_rid"] != 0x2000 or desktop["integrity_rid"] != 0x2000:
            report["result"] = "unsupported_integrity_level"
        elif desktop["in_any_job"]:
            report["result"] = "unsupported_desktop_foreign_job"
        else:
            report["result"] = "candidate_desktop_not_launch_verified"
            report["candidate"] = True
    except Exception as error:
        report["errors"].append(_public_error(error))
    finally:
        for handle in reversed(handles):
            try:
                api.close(handle)
            except Exception as error:
                report["errors"].append(_public_error(error))
        if report["errors"]:
            report.update(validity="unknown", result="observation_unknown", candidate=False)
    return report


def _public_error(error):
    # Exception text can contain paths or token values. Only constant stages and
    # numeric OS errors from this adapter are published.
    if isinstance(error, ObservationError):
        return {"stage": error.stage, "win32_error": error.win32_error}
    return {"stage": "unexpected_observation_error", "error_type": type(error).__name__}


def validate_output(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Output must be an absolute isolated path")
    resolved = path.resolve(strict=False)
    if any(part.casefold() == ".resource-sentinel" for part in (*path.parts, *resolved.parts)):
        raise ValueError("Production data directory is forbidden")
    if not resolved.parent.is_dir() or path.is_symlink() or resolved.exists():
        raise ValueError("Output requires an existing isolated directory and a new file")
    # The new file is created exclusively before any native reads. No overwrite,
    # replace or rename behavior can clobber another experiment's evidence.
    return resolved


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args(argv)
    output = validate_output(options.output)
    with output.open("x", encoding="utf-8") as stream:
        result = observe()
        json.dump(result, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return 0 if result["candidate"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
