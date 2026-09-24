"""Verified external-console source entry for the actual S2 producer closure.

Source verification creates no native context, demand, host, work or artifact.
The production-host/daily-demand scope has not yet been connected here, so this
entry cannot run measurements or publish S2. Pins are consistency data only.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys


def _load_bootstrap():
    path = Path(__file__).with_name("adaptive_producer_bootstrap.py")
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("s2_bootstrap_path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("s2_bootstrap_redirected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= 1024 * 1024:
        raise RuntimeError("s2_bootstrap_file_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(1024 * 1024 + 1)
        closed = os.fstat(stream.fileno())
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def signature(info, names):
        return tuple(getattr(info, key, None) for key in names)
    if (len(raw) != before.st_size or signature(before, (*fields, "st_ctime_ns")) !=
            signature(after, (*fields, "st_ctime_ns")) or signature(opened, (*fields, "st_ctime_ns")) !=
            signature(closed, (*fields, "st_ctime_ns")) or signature(before, fields) != signature(opened, fields)):
        raise RuntimeError("s2_bootstrap_source_changed")
    name = "_sentinel_producer_bootstrap"
    if name in sys.modules:
        raise RuntimeError("s2_bootstrap_preloaded")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


if __name__ == "__main__":
    _parser = argparse.ArgumentParser(description="Verify the real S2 source closure without native work.")
    _parser.add_argument("--check-source", action="store_true")
    _args = _parser.parse_args()
    try:
        _module = _load_bootstrap()
        # The original real module frame is required, never an injected factory.
        _bootstrap = _module.bootstrap()
        _producer = _bootstrap.modules["tests.windows.adaptive_launch_producer"]
        _pin = _producer._source_pin(_bootstrap)
    except BaseException as _error:
        print(json.dumps(dict(status="bootstrap_failed", error_type=type(_error).__name__, promotion=False)))
        raise SystemExit(1)
    if _args.check_source:
        print(json.dumps(dict(status="source_verified", source_pin=_pin, promotion=False), sort_keys=True))
        raise SystemExit(0)
    print(json.dumps(dict(status="blocked", reason="s2_original_production_host_scope_unavailable",
                          producer_native_work_started=False, promotion=False), sort_keys=True))
    raise SystemExit(2)
