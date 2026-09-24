"""Actual CPython import provenance for an activated daily source generation.

This stdlib-only module is entered at the beginning of sentinel/__init__.py.
The exec audit event supplies the actual module code object, including global
initializers and decorator calls. A file hash or function-name scan cannot
provide this evidence. This is cooperative version fencing, not a Python
security sandbox; an adversarial process in the same user is outside scope.
"""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import threading
import types


MAX_MODULES = 1024
_BOOTSTRAP_CODE = sys._getframe().f_code
_OBSERVER = None
_LOCK = threading.RLock()


class ImportProvenanceUnavailable(RuntimeError):
    pass


# Intentional stdlib-only duplication of daily_generation's structural schema:
# this observer executes before the runtime can be imported and attested.
# Keep the producer bootstrap's independent pre-import copy in agreement too.
_CODE_ATTRIBUTES = frozenset({
    "co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
    "co_stacksize", "co_flags", "co_code", "co_consts", "co_names", "co_varnames",
    "co_freevars", "co_cellvars", "co_name", "co_qualname", "co_filename",
    "co_firstlineno", "co_linetable", "co_exceptiontable",
    "co_lines", "co_positions", "co_lnotab",
})
_CODE_LAYOUT_VERIFIED = False


def _constant_key(value):
    kind = type(value)
    if value is None:
        return ("none",)
    if value is Ellipsis:
        return ("ellipsis",)
    if kind is bool:
        return ("bool", value)
    if kind is int:
        return ("int", value)
    if kind is str:
        return ("str", value)
    if kind is bytes:
        return ("bytes", value)
    if kind is float:
        return ("float", struct.pack(">d", value))
    if kind is complex:
        return ("complex", struct.pack(">d", value.real), struct.pack(">d", value.imag))
    if kind is tuple:
        return ("tuple", tuple(_constant_key(item) for item in value))
    if kind is frozenset:
        counts = {}
        for item in value:
            key = _constant_key(item)
            counts[key] = counts.get(key, 0) + 1
        return ("frozenset", frozenset(counts.items()))
    if kind is types.CodeType:
        return _code_key(value)
    raise ImportProvenanceUnavailable("daily_import_code_unverified")


def _code_key(code):
    global _CODE_LAYOUT_VERIFIED
    if type(code) is not types.CodeType:
        raise ImportProvenanceUnavailable("daily_import_code_unverified")
    if not _CODE_LAYOUT_VERIFIED:
        if frozenset(name for name in dir(types.CodeType) if name.startswith("co_")) != _CODE_ATTRIBUTES:
            raise ImportProvenanceUnavailable("daily_import_code_unverified")
        _CODE_LAYOUT_VERIFIED = True
    # Filename is normalized only after the caller checks the exact origin.
    # co_lines/co_positions/co_lnotab are derived from these persisted fields.
    return ("code", code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
            code.co_nlocals, code.co_stacksize, code.co_flags, code.co_code,
            code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
            code.co_name, code.co_qualname, code.co_firstlineno, code.co_linetable,
            code.co_exceptiontable, tuple(_constant_key(value) for value in code.co_consts))


class ImportObserver:
    """Original in-process observed code; no JSON or environment constructor."""
    def __init__(self, root, *, initial_code):
        self.root = Path(root).resolve(strict=True)
        self._code = {str(self.root / "sentinel/__init__.py"): _code_key(initial_code),
                      str(self.root / "sentinel_daily_bootstrap.py"): _code_key(_BOOTSTRAP_CODE)}
        self._failed = False
        self._probe = object()
        self._probe_seen = False
        self._lock = threading.RLock()

    def audit(self, event, args):
        if event == "resource_sentinel.import_provenance":
            if len(args) == 1 and args[0] is self._probe:
                self._probe_seen = True
            return
        if event != "exec" or len(args) != 1 or type(args[0]) is not types.CodeType:
            return
        code = args[0]
        if code.co_name != "<module>" or code.co_filename.startswith("<"):
            return
        try:
            path = Path(code.co_filename).resolve()
            relative = path.relative_to(self.root)
        except (ValueError, OSError):
            return
        if not relative.parts or relative.parts[0] != "sentinel" or path.suffix != ".py":
            return
        with self._lock:
            key = str(path)
            if len(self._code) >= MAX_MODULES and key not in self._code:
                self._failed = True
                return
            try:
                observed = _code_key(code)
            except ImportProvenanceUnavailable:
                self._failed = True
                raise
            previous = self._code.get(key)
            if previous is not None and previous != observed:
                self._failed = True
            self._code[key] = observed

    def assert_modules(self, source_root, sources, *, modules=None):
        """Compare complete executed module code to the pinned source bytes."""
        if Path(source_root).resolve() != self.root or self._failed or not self._probe_seen:
            raise ImportProvenanceUnavailable("daily_import_provenance_unavailable")
        modules = sys.modules if modules is None else modules
        with self._lock:
            bootstrap = sources.get("sentinel_daily_bootstrap.py")
            if bootstrap is None or _code_key(compile(bootstrap, "<pin>", "exec", dont_inherit=True)) != \
                    self._code[str(self.root / "sentinel_daily_bootstrap.py")]:
                raise ImportProvenanceUnavailable("daily_bootstrap_generation_mismatch")
            for name, module in tuple(modules.items()):
                if not (name == "sentinel" or name.startswith("sentinel.")) or module is None:
                    continue
                try:
                    path = Path(module.__file__).resolve(strict=True)
                    relative = path.relative_to(self.root).as_posix()
                    specification = module.__spec__
                    if specification is None or getattr(specification, "_initializing", False):
                        raise ValueError
                except (ValueError, OSError, AttributeError, TypeError):
                    raise ImportProvenanceUnavailable("daily_import_completion_unverified") from None
                data = sources.get(relative)
                observed = self._code.get(str(path))
                if data is None or observed is None:
                    raise ImportProvenanceUnavailable("daily_loaded_import_unobserved")
                expected = _code_key(compile(data, str(path), "exec", dont_inherit=True))
                if expected != observed:
                    raise ImportProvenanceUnavailable("daily_executed_module_generation_mismatch")


def observe_package_import():
    """Called directly by sentinel/__init__.py, before other Sentinel imports."""
    global _OBSERVER
    frame = sys._getframe(1)
    try:
        path = Path(frame.f_code.co_filename).resolve(strict=True)
        if frame.f_globals.get("__name__") != "sentinel" or path.name != "__init__.py" or path.parent.name != "sentinel":
            raise ImportProvenanceUnavailable("daily_bootstrap_entrypoint_invalid")
        root = path.parent.parent
        with _LOCK:
            if _OBSERVER is not None:
                if _OBSERVER.root != root:
                    raise ImportProvenanceUnavailable("daily_bootstrap_origin_changed")
                return _OBSERVER
            if any(name.startswith("sentinel.") for name in sys.modules):
                raise ImportProvenanceUnavailable("daily_bootstrap_started_too_late")
            observer = ImportObserver(root, initial_code=frame.f_code)
            sys.addaudithook(observer.audit)
            sys.audit("resource_sentinel.import_provenance", observer._probe)
            if not observer._probe_seen:
                raise ImportProvenanceUnavailable("daily_import_audit_not_installed")
            _OBSERVER = observer
            return observer
    finally:
        del frame


def assert_import_provenance(source_root, sources):
    if _OBSERVER is None:
        raise ImportProvenanceUnavailable("daily_bootstrap_not_installed")
    return _OBSERVER.assert_modules(source_root, sources)
