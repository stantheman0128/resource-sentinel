"""Isolated external-console S1 entry; imports only stdlib before attestation.

This does not activate the daily source generation or enable adaptive control.
The canonical daily runtime must separately support the original experiment
protocol. A failure never retries measurements; only retained cleanup continues.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time


_MAX_BOOTSTRAP_BYTES = 1024 * 1024
_RUN = None
_FAILURES = []


def _retain(error):
    # Retain original causes without an unbounded log on repeated cleanup ticks.
    if not any(item is error for item in _FAILURES) and len(_FAILURES) < 16:
        _FAILURES.append(error)


def _emit(value):
    try:
        print(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False), flush=True)
        return True
    except BaseException as error:
        _retain(error)
        return False


def _load_bootstrap():
    path = Path(__file__).with_name("adaptive_producer_bootstrap.py")
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("s1_bootstrap_path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("s1_bootstrap_redirected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= _MAX_BOOTSTRAP_BYTES:
        raise RuntimeError("s1_bootstrap_file_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(_MAX_BOOTSTRAP_BYTES + 1)
        closed = os.fstat(stream.fileno())
    after = path.stat()
    shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def signature(info, fields):
        return tuple(getattr(info, key, None) for key in fields)
    if (len(raw) != before.st_size or signature(before, (*shared, "st_ctime_ns")) !=
            signature(after, (*shared, "st_ctime_ns")) or signature(opened, (*shared, "st_ctime_ns")) !=
            signature(closed, (*shared, "st_ctime_ns")) or signature(before, shared) != signature(opened, shared)):
        raise RuntimeError("s1_bootstrap_source_changed")
    name = "_sentinel_producer_bootstrap"
    if name in sys.modules:
        raise RuntimeError("s1_bootstrap_preloaded")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    # bootstrap() later verifies this complete executed code and its own entry
    # frame against the pinned source; the loader never executes a pyc cache.
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def _context_cleanup(run, primary):
    """Close only original read-only identity owners; never reacquire context.

    A retained WTS buffer has an unknown allocation/free outcome and cannot be
    retried by numeric pointer. Keep the original reader alive in that case.
    A known failed identity CloseHandle uses its existing quarantine-aware API.
    """
    original = getattr(run, "_source_original", None)
    reader = original[3] if original is not None else getattr(run, "context_source", None)
    if reader is None:
        return False
    from sentinel.adaptive.identity import retry_identity_cleanup
    roots = (primary, getattr(reader, "_failure", None))
    pending, seen, unresolved = list(roots), set(), False
    while pending:
        error = pending.pop()
        if not isinstance(error, BaseException) or id(error) in seen:
            continue
        seen.add(id(error))
        if len(seen) > 32:
            unresolved = True
            break
        if getattr(error, "_identity_handle_cleanup", ()):
            try:
                retry_identity_cleanup(error)
            except BaseException as cleanup_error:
                _retain(cleanup_error)
            unresolved |= bool(getattr(error, "_identity_handle_cleanup", ()))
        pending.extend((error.__cause__, error.__context__))
    current = getattr(reader, "_current", None)
    if current is not None:
        try:
            current.close()
            reader._current = None
        except BaseException as error:
            _retain(error)
            unresolved = True
    return unresolved or getattr(reader, "_pending_buffer", None) is not None


def _recover(run, runner, primary):
    provider = getattr(run, "_s1_provider", None)
    pending = False
    if getattr(run, "_s1_initialized", False):
        try:
            if runner.custody_pending(provider):
                # Uses only the original case/operation. Does not attest changed
                # source, poll admission, renew a clock or start a replacement.
                provider.recover_once()
            pending = runner.custody_pending(provider)
        except BaseException as error:
            _retain(error)
            pending = True
    try:
        pending |= _context_cleanup(run, primary)
    except BaseException as error:
        _retain(error)
        pending = True
    return pending


def _read_profile(path):
    """Read bounded configuration data, never executable source or daily state."""
    from sentinel.adaptive.decision import parse_policy_profile
    path = Path(path)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("s1_profile_path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("s1_profile_redirected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= 65536:
        raise RuntimeError("s1_profile_file_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(65537)
        closed = os.fstat(stream.fileno())
    after = path.stat()
    shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def signature(info, fields):
        return tuple(getattr(info, key, None) for key in fields)
    if (len(raw) != before.st_size or signature(before, (*shared, "st_ctime_ns")) !=
            signature(after, (*shared, "st_ctime_ns")) or signature(opened, (*shared, "st_ctime_ns")) !=
            signature(closed, (*shared, "st_ctime_ns")) or signature(before, shared) != signature(opened, shared)):
        raise RuntimeError("s1_profile_changed")
    # Enforce cannot be selected by configuration. Native S1 probes remain
    # isolated capability measurements; this never updates production mode.
    return parse_policy_profile(raw)


def _run(bootstrap, directory, profile):
    global _RUN
    runner = bootstrap.modules["tests.windows.adaptive_capability_runner"]
    # Retain even a partly initialized run/context source after a constructor
    # failure. Neither a log error nor Ctrl-C may drop its cleanup obligation.
    _RUN = run = runner.NativeEvidenceRun.__new__(runner.NativeEvidenceRun)
    try:
        runner.NativeEvidenceRun.__init__(run, directory, profile, bootstrap=bootstrap)
        result = run.run_s1()
        return 0 if _emit(dict(status="complete", **result)) else 1
    except BaseException as primary:
        _retain(primary)
        _emit(dict(status="failed", errors=runner.error_evidence(primary, stage="s1"), promotion=False))
        announced = False
        while True:
            try:
                if not _recover(run, runner, primary):
                    _emit(dict(status="failed_cleanup_complete", promotion=False))
                    return 1
                if not announced:
                    announced = _emit(dict(status="cleanup_pending", keep_console_open=True, promotion=False))
                time.sleep(.25)
            except BaseException as error:
                _retain(error)


def _parser():
    parser = argparse.ArgumentParser(description="Measure isolated S1 with original daily admission; never deploys.")
    parser.add_argument("--directory", type=Path, help="Absolute isolated evidence directory outside daily data.")
    parser.add_argument("--profile", type=Path,
        help="Absolute off/shadow policy JSON; read only and bound into the evidence revision.")
    parser.add_argument("--check-source", action="store_true",
        help="Verify actual source imports only; no native context, admission, measurement or artifact.")
    return parser


if __name__ == "__main__":
    _argument_parser = _parser()
    _args = _argument_parser.parse_args()
    if not _args.check_source and (_args.directory is None or _args.profile is None):
        _argument_parser.error("--directory and --profile are required for measurement")
    try:
        _module = _load_bootstrap()
        # Must stay directly in this real module frame, not inside _run/main.
        _bootstrap = _module.bootstrap()
    except BaseException as _error:
        _retain(_error)
        _emit(dict(status="bootstrap_failed", error_type=type(_error).__name__, promotion=False))
        raise SystemExit(1)
    if _args.check_source:
        _build = _bootstrap.assert_unchanged()
        raise SystemExit(0 if _emit(dict(status="source_verified", promotion=False,
            source_digest=_bootstrap.source_binding.source_digest,
            runtime_sha256=_build.runtime_sha256, producer_sha256=_build.producer_sha256)) else 1)
    try:
        _profile = _read_profile(_args.profile)
    except BaseException as _error:
        _retain(_error)
        _emit(dict(status="profile_failed", error_type=type(_error).__name__, promotion=False))
        raise SystemExit(1)
    raise SystemExit(_run(_bootstrap, _args.directory, _profile))
