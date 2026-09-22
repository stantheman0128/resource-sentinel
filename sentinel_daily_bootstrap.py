"""Actual CPython import provenance for an activated daily source generation.

This stdlib-only module is entered at the beginning of sentinel/__init__.py.
The exec audit event supplies the actual module code object, including global
initializers and decorator calls. A file hash or function-name scan cannot
provide this evidence. This is cooperative version fencing, not a Python
security sandbox; an adversarial process in the same user is outside scope.
"""
from __future__ import annotations

from pathlib import Path
import sys
import threading
import types


MAX_MODULES = 1024
_BOOTSTRAP_CODE = sys._getframe().f_code
_OBSERVER = None
_LOCK = threading.RLock()


class ImportProvenanceUnavailable(RuntimeError):
    pass


def _normal(code):
    return code.replace(co_filename="<source-generation>", co_consts=tuple(
        _normal(item) if isinstance(item, types.CodeType) else item for item in code.co_consts))


class ImportObserver:
    """Original in-process observed code; no JSON or environment constructor."""
    def __init__(self, root, *, initial_code):
        self.root = Path(root).resolve(strict=True)
        self._code = {str(self.root / "sentinel/__init__.py"): _normal(initial_code),
                      str(self.root / "sentinel_daily_bootstrap.py"): _normal(_BOOTSTRAP_CODE)}
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
            observed = _normal(code)
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
            if bootstrap is None or _normal(compile(bootstrap, "<pin>", "exec", dont_inherit=True)) != \
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
                expected = _normal(compile(data, str(path), "exec", dont_inherit=True))
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
