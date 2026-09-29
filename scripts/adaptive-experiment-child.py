"""Fixed ``python -I`` inert child; no ambient repository import path.

Only the adjacent reviewed source tree can supply Sentinel modules. The parent
binds this exact entry to its source manifest before Create. This loader adds no
authority: the child still authenticates its original parent before dispatch.
"""
from __future__ import annotations

import importlib.abc
import importlib.util
import os
from pathlib import Path
import stat
import sys


_ROOT = Path(__file__).parent.parent
_MAX_SOURCE = 2 * 1024 * 1024


def _source(path):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("experiment_child_source_path_invalid")
    for part in (path, *path.parents):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("experiment_child_source_redirected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= _MAX_SOURCE:
        raise RuntimeError("experiment_child_source_invalid")
    shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def sig(info, fields=shared):
        return tuple(getattr(info, key, None) for key in fields)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(_MAX_SOURCE + 1)
        closing = os.fstat(stream.fileno())
    after = path.stat()
    full = (*shared, "st_ctime_ns")
    if (len(raw) != before.st_size or sig(before) != sig(opened) or
            sig(before, full) != sig(after, full) or sig(opened, full) != sig(closing, full)):
        raise RuntimeError("experiment_child_source_changed")
    return raw


class _Loader(importlib.abc.Loader):
    def __init__(self, path):
        self.path = path

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        exec(compile(_source(self.path), str(self.path), "exec", dont_inherit=True), module.__dict__)


class _Finder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "sentinel_daily_bootstrap":
            source, package = _ROOT / "sentinel_daily_bootstrap.py", False
        elif fullname == "sentinel" or fullname.startswith("sentinel."):
            parts = fullname.split(".")
            if any(not part.isidentifier() for part in parts):
                raise ImportError("experiment_child_source_name_invalid")
            base = _ROOT.joinpath(*parts)
            package = (base / "__init__.py").is_file()
            source = base / "__init__.py" if package else base.with_suffix(".py")
        else:
            return None
        # No alternate finder/pyc fallback if a fixed source is absent.
        if not source.is_file():
            raise ImportError("experiment_child_source_missing")
        return importlib.util.spec_from_file_location(fullname, source, loader=_Loader(source),
            submodule_search_locations=[str(source.parent)] if package else None)


def main():
    if not sys.flags.isolated or not sys.flags.ignore_environment:
        raise RuntimeError("experiment_child_isolated_python_required")
    if any(name == "sentinel_daily_bootstrap" or name == "sentinel" or name.startswith("sentinel.")
           for name in sys.modules):
        raise RuntimeError("experiment_child_source_preloaded")
    _source(Path(__file__))
    sys.meta_path.insert(0, _Finder())
    from sentinel.adaptive.experiment_child_host import main as run
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
