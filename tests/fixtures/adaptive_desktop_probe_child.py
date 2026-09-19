"""Test-only, read-only self probe with a short parent-issued handshake ticket.

There is deliberately no target PID, payload, process launcher, control API or
retry option. The parent must independently verify the live process before ACK.
Run only through the separately admitted, isolated desktop probe controller.
Ticket/ACK deadlines are checked between synchronous reads; they are not an OS
hard lifetime limit if storage or a native query stalls. The controller requires
local fixed storage. Network/device path spellings are also refused here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import ntpath
import os
from pathlib import Path
import re
import stat
import time


MAX_JSON_BYTES = 16 * 1024
MAX_TICKET_SECONDS = 15.0
ACK_SECONDS = 10.0
NONCE_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
REPARSE_POINT = 0x400
OUTPUT_NAMES = frozenset(("ready.json", "done.json"))


class ProtocolError(Exception):
    """Only fixed, non-private reason strings may be passed by this module."""


class TicketExpired(ProtocolError):
    pass


def _is_redirected(path, info):
    return path.is_symlink() or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def validate_run_directory(value, nonce):
    if not isinstance(nonce, str) or not NONCE_PATTERN.fullmatch(nonce):
        raise ProtocolError("nonce_invalid")
    directory = Path(value)
    if os.fspath(value).replace("\\", "/").startswith("//"):
        raise ProtocolError("network_or_device_path_forbidden")
    if not directory.is_absolute() or ".." in directory.parts or directory.name != nonce:
        raise ProtocolError("run_directory_invalid")
    if any(part.casefold() == ".resource-sentinel" for part in directory.parts):
        raise ProtocolError("production_directory_forbidden")
    # Reject redirects at every ancestor, including Windows junctions. Resolving
    # an alias and then merely checking its final basename is not sufficient.
    for component in (directory, *directory.parents):
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or _is_redirected(component, info):
            raise ProtocolError("run_directory_redirected_or_not_directory")
    resolved = directory.resolve(strict=True)
    if any(part.casefold() == ".resource-sentinel" for part in resolved.parts):
        raise ProtocolError("production_directory_forbidden")
    return directory


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("json_duplicate_key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ProtocolError("json_nonfinite_number")


def _finite_tree(value):
    if isinstance(value, float) and not math.isfinite(value):
        raise ProtocolError("json_nonfinite_number")
    if isinstance(value, dict):
        for item in value.values():
            _finite_tree(item)
    elif isinstance(value, list):
        for item in value:
            _finite_tree(item)


def read_json(directory, nonce, name):
    if name not in ("request.json", "ack.json"):
        raise ProtocolError("input_filename_invalid")
    directory = validate_run_directory(directory, nonce)
    path = directory / name
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or _is_redirected(path, before):
        raise ProtocolError("input_not_regular_file")
    if before.st_size > MAX_JSON_BYTES:
        raise ProtocolError("json_too_large")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ProtocolError("input_identity_changed")
        if not stat.S_ISREG(opened.st_mode) or getattr(opened, "st_file_attributes", 0) & REPARSE_POINT:
            raise ProtocolError("input_not_regular_file")
        raw = stream.read(MAX_JSON_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > MAX_JSON_BYTES:
        raise ProtocolError("json_too_large")
    if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ProtocolError("input_changed_during_read")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ProtocolError("json_object_required")
    _finite_tree(value)
    return value


def _number(value):
    return type(value) in (int, float) and math.isfinite(value)


def validate_ticket(ticket, nonce, now):
    expected = {"schema_version", "nonce", "issued_monotonic", "deadline_monotonic", "expected_python_basename"}
    if set(ticket) != expected or type(ticket["schema_version"]) is not int or ticket["schema_version"] != 1:
        raise ProtocolError("ticket_schema_invalid")
    if ticket["nonce"] != nonce or ticket["expected_python_basename"] != "pythonw.exe":
        raise ProtocolError("ticket_identity_invalid")
    issued, deadline = ticket["issued_monotonic"], ticket["deadline_monotonic"]
    if not all(_number(value) for value in (issued, deadline, now)) or issued < 0 or now < 0:
        raise ProtocolError("ticket_clock_invalid")
    if deadline != issued + MAX_TICKET_SECONDS or deadline - issued > MAX_TICKET_SECONDS:
        raise ProtocolError("ticket_duration_invalid")
    if issued > now + 0.1:
        raise ProtocolError("ticket_from_future")
    if now >= deadline:
        raise TicketExpired("ticket_expired")
    return float(deadline)


def ack_matches(ack, nonce):
    return (set(ack) == {"schema_version", "nonce", "accepted"}
            and type(ack["schema_version"]) is int and ack["schema_version"] == 1
            and ack["nonce"] == nonce and ack["accepted"] is True)


def publish_json(directory, nonce, name, payload):
    """Publish once: exclusive same-directory temporary file, then no overwrite."""
    if name not in OUTPUT_NAMES:
        raise ProtocolError("output_filename_invalid")
    directory = validate_run_directory(directory, nonce)
    target, temporary = directory / name, directory / (name + ".pending")
    if os.path.lexists(target) or os.path.lexists(temporary):
        raise ProtocolError("output_already_exists")
    encoded = json.dumps(payload, allow_nan=False, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise ProtocolError("output_too_large")
    # Leave a failed pending file as evidence rather than deleting/reusing it.
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    validate_run_directory(directory, nonce)
    if os.name == "nt":
        # Windows os.rename fails if the destination exists; never os.replace.
        os.rename(temporary, target)
    else:
        # Pure file fixtures can run on other platforms without POSIX rename's
        # overwrite semantics. Linking is an atomic exclusive destination create.
        os.link(temporary, target, follow_symlinks=False)
        temporary.unlink()


def load_preflight():
    source = Path(__file__).resolve().parents[1] / "windows" / "probe_adaptive_desktop.py"
    specification = importlib.util.spec_from_file_location("adaptive_desktop_child_read_only", source)
    if specification is None or specification.loader is None:
        raise ProtocolError("preflight_import_unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def observe_self(module, api=None):
    api = module.NativeReadOnly() if api is None else api
    own_pid = os.getpid()
    handle = api.open_process(own_pid)
    try:
        first = api.read_process(handle, own_pid)
        second = api.read_process(handle, own_pid)
        if first != second or first["pid"] != own_pid:
            raise ProtocolError("self_identity_changed")
        # This filter is a self-report only. The parent's held-handle token and
        # exact image/birth verification remains mandatory before it sends ACK.
        # Job membership is an observation, not an identity failure. A known
        # in-Job child can complete this diagnostic handshake but cannot become
        # a supported control host. The controller enforces that separately.
        supported = (type(first["in_any_job"]) is bool and first["elevated"] is False
                     and type(first["integrity_rid"]) is int and first["integrity_rid"] == 0x2000
                     and ntpath.basename(first["image_path"]).casefold() == "pythonw.exe")
        return module._public_process(first), supported
    finally:
        api.close(handle)


def collect_self_diagnostics(module, identity, *, api, clock, deadline, collector=None):
    """Collect after identity ACK; do not keep an unverified child waiting on it."""
    if collector is None:
        source = Path(__file__).resolve().parents[1] / "windows" / "adaptive_job_diagnostics.py"
        specification = importlib.util.spec_from_file_location("adaptive_child_diagnostics", source)
        if specification is None or specification.loader is None:
            raise ProtocolError("diagnostics_import_unavailable")
        diagnostics = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(diagnostics)
        collector = diagnostics.collect_diagnostics
    if clock() >= deadline:
        raise TicketExpired("ticket_expired")
    handle = api.open_process(os.getpid())
    try:
        first = api.read_process(handle, os.getpid())
        if module._public_process(first) != identity:
            raise ProtocolError("self_identity_changed")
        result = collector(api, handle, first, clock=clock, deadline=deadline)
        if clock() >= deadline:
            raise TicketExpired("ticket_expired")
        if first != api.read_process(handle, os.getpid()):
            raise ProtocolError("self_identity_changed")
        return result
    finally:
        api.close(handle)


def _error(error):
    if isinstance(error, ProtocolError):
        return {"stage": str(error)}  # All callers above supply constant reasons.
    code = getattr(error, "win32_error", None)
    if type(code) is int:
        return {"stage": "self_observation_failed", "win32_error": code}
    return {"stage": "unexpected_probe_error"}


def run_probe(run_directory, nonce, *, api=None, preflight_module=None, clock=None, sleeper=None,
              diagnostic_collector=None):
    clock, sleeper = clock or time.monotonic, sleeper or time.sleep
    # A rejected path must never receive an error report or any other write.
    try:
        directory = validate_run_directory(run_directory, nonce)
    except Exception:
        return 2
    result = {"schema_version": 1, "nonce": nonce, "outcome": "observation_unknown", "errors": []}
    try:
        for name in ("ready.json", "ready.json.pending", "ack.json", "done.json", "done.json.pending"):
            if os.path.lexists(directory / name):
                raise ProtocolError("run_directory_already_used")
        ticket = read_json(directory, nonce, "request.json")
        deadline = validate_ticket(ticket, nonce, clock())
        module = preflight_module if preflight_module is not None else load_preflight()
        # Importing the adapter does not call Win32. Recheck the ticket before
        # NativeReadOnly construction and after its two held-handle observations.
        validate_ticket(ticket, nonce, clock())
        api = module.NativeReadOnly() if api is None else api
        identity, supported = observe_self(module, api)
        result["process"] = identity
        validate_ticket(ticket, nonce, clock())
        if not supported:
            raise ProtocolError("unsupported_self_identity")
        publish_json(directory, nonce, "ready.json", {"schema_version": 1, "nonce": nonce, "process": identity})
        ack_deadline = min(clock() + ACK_SECONDS, deadline)
        while True:
            now = clock()
            if now >= ack_deadline:
                result["outcome"] = "ticket_expired" if now >= deadline else "ack_timeout"
                break
            if os.path.lexists(directory / "ack.json"):
                ack = read_json(directory, nonce, "ack.json")
                if not ack_matches(ack, nonce):
                    raise ProtocolError("ack_invalid")
                now = clock()
                if now >= ack_deadline:
                    result["outcome"] = "ticket_expired" if now >= deadline else "ack_timeout"
                else:
                    result["outcome"] = "acknowledged"
                break
            sleeper(min(0.05, ack_deadline - now))
        if result["outcome"] == "acknowledged":
            # ACK only confirms the parent's independent identity observation;
            # it grants no enrollment/control. Queries happen while the parent
            # still holds the exact child handle and remain within this ticket.
            result["diagnostics"] = collect_self_diagnostics(
                module, identity, api=api, clock=clock, deadline=deadline,
                collector=diagnostic_collector)
            validate_ticket(ticket, nonce, clock())
    except TicketExpired as error:
        result["outcome"] = "ticket_expired"
        result["errors"].append(_error(error))
    except Exception as error:
        result["errors"].append(_error(error))
    finally:
        try:
            publish_json(directory, nonce, "done.json", result)
        except Exception:
            # An existing done file or failed publication can never be success.
            return 2
    return 0 if result["outcome"] == "acknowledged" and not result["errors"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-directory", required=True, type=Path)
    parser.add_argument("--nonce", required=True)
    arguments = parser.parse_args(argv)
    return run_probe(arguments.run_directory, arguments.nonce)


if __name__ == "__main__":
    raise SystemExit(main())
