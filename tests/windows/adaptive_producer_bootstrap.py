"""Original, source-only capability imports; no admission or native authority.

The isolated console loads this stdlib-only module as
``_sentinel_producer_bootstrap`` using compile/exec, then calls ``bootstrap()``
directly at module level. This attests that actual entry frame, this module and
the finite fixture closure, not an arbitrary caller's claimed source hashes.
The canonical daily manifest and concrete two-root inventory remain separate
checks. This is cooperative version fencing, not a Python security sandbox.
"""
from __future__ import annotations

import importlib
import importlib.abc
import importlib.util
import os
from pathlib import Path
import stat
import struct
import sys
import threading
import types
from types import MappingProxyType


_BOOTSTRAP_CODE = sys._getframe().f_code
_PRIVATE_NAME = "_sentinel_producer_bootstrap"
_PUBLIC_NAME = "tests.windows.adaptive_producer_bootstrap"
_ENTRY = "tests/windows/run_adaptive_s1.py"
_MODULES = (
    ("tests.windows.adaptive_scope_launch", "tests/windows/adaptive_scope_launch.py"),
    ("tests.windows.adaptive_s1_provider", "tests/windows/adaptive_s1_provider.py"),
    ("tests.windows.adaptive_capability_runner", "tests/windows/adaptive_capability_runner.py"),
    ("tests.windows.adaptive_s1_measurements", "tests/windows/adaptive_s1_measurements.py"),
)
_NAMESPACES = ("tests", "tests.windows", "tests.fixtures", "tests.benchmarks")
_EXTRA_FILES = (_ENTRY, "tests/windows/adaptive_producer_bootstrap.py",
                "tests/windows/adaptive_scope_wrapper.py", "tests/fixtures/adaptive_scope_cpu_worker.py")
_S2_CHILD = "tests/fixtures/adaptive_launch_producer_child.py"
_S2_ENTRY = "tests/windows/run_adaptive_s2.py"
_S2_CHILD_MODULES = (
    ("tests.windows.adaptive_win32", "tests/windows/adaptive_win32.py"),
)
_S2_MODULES = (*_S2_CHILD_MODULES,
    ("tests.fixtures.adaptive_launch_producer_child", _S2_CHILD),
    ("tests.windows.adaptive_launch_producer", "tests/windows/adaptive_launch_producer.py"),
)
# Entry selection comes only from the original executing module frame. Neither
# argv, a source digest, nor a payload may widen this finite import closure.
_PROFILES = {
    _ENTRY: (_MODULES, _EXTRA_FILES),
    _S2_CHILD: (_S2_CHILD_MODULES, (_S2_CHILD, "tests/windows/adaptive_producer_bootstrap.py")),
    _S2_ENTRY: (_S2_MODULES, (_S2_ENTRY, "tests/windows/adaptive_producer_bootstrap.py")),
}
_MAX_FILE_BYTES = 1024 * 1024
_ORIGINAL = None


class ProducerBootstrapError(RuntimeError):
    pass


def _fail(reason):
    raise ProducerBootstrapError("producer_bootstrap_" + reason)


def _safe(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        _fail("absolute_path_required")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            _fail("redirected_path")
    if path.resolve(strict=True) != path:
        _fail("aliased_path")
    info = path.stat()
    if (not info.st_ino or
            not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        _fail("path_type_invalid")
    return path


def _identity(path):
    info = path.stat()
    return info.st_dev, info.st_ino


# Intentional duplicate of the reviewed daily bootstrap/runtime schema. This
# pre-import fixture verifier cannot import either runtime implementation to
# decide whether the imports themselves are the reviewed original code.
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
    _fail("code_unverified")


def _code_key(code):
    global _CODE_LAYOUT_VERIFIED
    if type(code) is not types.CodeType:
        _fail("code_unverified")
    if not _CODE_LAYOUT_VERIFIED:
        if frozenset(name for name in dir(types.CodeType) if name.startswith("co_")) != _CODE_ATTRIBUTES:
            _fail("code_unverified")
        _CODE_LAYOUT_VERIFIED = True
    return ("code", code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
            code.co_nlocals, code.co_stacksize, code.co_flags, code.co_code,
            code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
            code.co_name, code.co_qualname, code.co_firstlineno, code.co_linetable,
            code.co_exceptiontable, tuple(_constant_key(value) for value in code.co_consts))


class _Source:
    def __init__(self, path):
        self.path = _safe(path)
        self.data, self.identity = self._read()

    def _read(self):
        _safe(self.path)
        before = self.path.stat()
        if before.st_size > _MAX_FILE_BYTES:
            _fail("source_oversized")
        with self.path.open("rb") as stream:
            opened_before = os.fstat(stream.fileno())
            data = stream.read(_MAX_FILE_BYTES + 1)
            opened_after = os.fstat(stream.fileno())
        after = self.path.stat()
        # CPython 3.13 on this Windows host reports path-stat ctime as birthtime,
        # but fstat ctime as change time. Compare each full signature with its
        # own before/after observation, retaining BOTH across later reads; only
        # fields with the same meaning are compared across path and open handle.
        shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
        fields = (*shared, "st_ctime_ns")
        def signature(info, names=fields):
            return tuple(getattr(info, field, None) for field in names)
        path_signature, handle_signature = signature(before), signature(opened_before)
        if (len(data) != before.st_size or path_signature != signature(after) or
                handle_signature != signature(opened_after) or
                signature(before, shared) != signature(opened_before, shared)):
            _fail("source_changed")
        return data, (path_signature, handle_signature)

    def verify(self):
        if self._read() != (self.data, self.identity):
            _fail("source_changed")

    def compile(self):
        return compile(self.data, str(self.path), "exec", dont_inherit=True)


def _members(module):
    """Pin source-defined callable identities, including class descriptors."""
    result = []
    def function(label, value):
        if type(value) is types.FunctionType and value.__module__ == module.__name__:
            result.append((label, value, value.__code__))
    for name, value in tuple(vars(module).items()):
        function(name, value)
        if isinstance(value, type) and value.__module__ == module.__name__:
            result.append((name, value, None))
            for child_name, child in tuple(vars(value).items()):
                label = name + "." + child_name
                if isinstance(child, (classmethod, staticmethod)):
                    child = child.__func__
                if isinstance(child, property):
                    for suffix, accessor in (("get", child.fget), ("set", child.fset), ("del", child.fdel)):
                        function(label + "." + suffix, accessor)
                else:
                    function(label, child)
    return tuple(result)


def _bindings(module):
    # Imported classes/functions/modules determine the API actually called.
    # Pin their original binding identity, not mutable custody object contents.
    # Later ordinary submodule imports may add package attributes; every loaded
    # runtime module also has its exact parent attribute verified separately.
    return tuple((name, value) for name, value in tuple(vars(module).items())
                 if isinstance(value, types.ModuleType) or callable(value))


class _Module:
    def __init__(self, name, module, source, code):
        if _code_key(code) != _code_key(source.compile()):
            _fail("executed_code_changed")
        self.name, self.module, self.source, self.code = name, module, source, code
        self.spec = module.__spec__
        self.loader = getattr(module, "__loader__", None)
        self.members = _members(module)
        self.bindings = _bindings(module)

    def verify(self):
        members = _members(self.module)
        if (sys.modules.get(self.name) is not self.module or
                self.module.__spec__ is not self.spec or
                getattr(self.module, "__loader__", None) is not self.loader or
                getattr(self.spec, "_initializing", False) or
                getattr(self.module, "__file__", None) != str(self.source.path) or
                any(vars(self.module).get(name) is not value for name, value in self.bindings) or
                len(members) != len(self.members) or any(
                    current[0] != original[0] or current[1] is not original[1] or current[2] is not original[2]
                    for current, original in zip(members, self.members))):
            _fail("module_identity_changed")
        self.source.verify()


class _CheckedLoader(importlib.abc.Loader):
    def __init__(self, finder, name, source):
        self.finder, self.name, self.source = finder, name, source

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        if self.name in self.finder.loaded:
            _fail("module_reexecution")
        self.source.verify()
        code = self.source.compile()
        module.__file__ = str(self.source.path)
        exec(code, module.__dict__)
        self.finder.loaded[self.name] = _Module(self.name, module, self.source, code)


class _CheckedFinder(importlib.abc.MetaPathFinder):
    def __init__(self, owner):
        self.owner, self.loaded = owner, {}

    def find_spec(self, fullname, path=None, target=None):
        source = self.owner._fixture_sources.get(fullname)
        package = False
        if fullname == "sentinel_daily_bootstrap" or fullname == "sentinel" or fullname.startswith("sentinel."):
            parts = fullname.split(".")
            if any(not part.isidentifier() for part in parts):
                _fail("runtime_module_invalid")
            location = self.owner.runtime_root.joinpath(*parts)
            package = location.is_dir()
            location = location / "__init__.py" if package else location.with_suffix(".py")
            source = _Source(location)
            if self.owner.manifest is not None:
                relative = location.relative_to(self.owner.runtime_root).as_posix()
                entry = next((item for item in self.owner.manifest.entries if item.path == relative), None)
                import hashlib
                if entry is None or entry.size != len(source.data) or entry.sha256 != hashlib.sha256(source.data).hexdigest():
                    _fail("runtime_generation_changed")
        elif source is None:
            if fullname == "tests" or fullname.startswith("tests."):
                raise ModuleNotFoundError("producer_bootstrap_unreviewed_fixture: " + fullname)
            return None
        loader = _CheckedLoader(self, fullname, source)
        return importlib.util.spec_from_file_location(fullname, source.path, loader=loader,
            submodule_search_locations=[] if package else None)


class ProducerBootstrap:
    """Retained in-process execution evidence; serialized values grant nothing."""
    def __init__(self, entry_frame, *, _token):
        if _token is not _BOOTSTRAP_CODE or type(self) is not ProducerBootstrap:
            _fail("original_bootstrap_required")
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._ready = False
        self.manifest = self.source_binding = self.build_source = None
        self._entry_module = sys.modules.get("__main__")
        self._bootstrap_module = sys.modules.get(_PRIVATE_NAME)
        if (entry_frame.f_code.co_name != "<module>" or
                self._entry_module is None or entry_frame.f_globals is not vars(self._entry_module) or
                self._bootstrap_module is None or vars(self._bootstrap_module) is not globals()):
            _fail("original_entry_required")
        entry_path = _safe(Path(entry_frame.f_code.co_filename))
        self.producer_root = _safe(Path(__file__).parents[2], directory=True)
        self.runtime_root = _safe(Path.home() / "Projects" / "resource-sentinel", directory=True)
        entries = [relative for relative in _PROFILES if entry_path == self.producer_root / relative]
        if len(entries) != 1:
            _fail("entry_path_invalid")
        self.entry = entries[0]
        self._modules, extras = _PROFILES[self.entry]
        self._profile = self.entry, self._modules, extras
        self._python = _Source(_safe(Path(sys.executable).resolve(strict=True)))
        self._roots = {path: _identity(path) for path in (self.producer_root, self.runtime_root)}
        self._directories = {self.producer_root / name.replace(".", "/"): None for name in _NAMESPACES}
        for directory in self._directories:
            self._directories[directory] = _identity(_safe(directory, directory=True))
        self._layout()
        sources = {relative: _Source(self.producer_root / relative)
                   for relative in (*extras, *(relative for _, relative in self._modules))}
        self._sources = sources
        self._fixture_sources = {name: sources[relative] for name, relative in self._modules}
        self._entry_record = _Module("__main__", self._entry_module, sources[self.entry], entry_frame.f_code)
        self._bootstrap_record = _Module(_PRIVATE_NAME, self._bootstrap_module,
            sources["tests/windows/adaptive_producer_bootstrap.py"], _BOOTSTRAP_CODE)
        self._namespaces = {}
        self._finder = _CheckedFinder(self)

    def _layout(self):
        for directory, identity in self._directories.items():
            if _identity(_safe(directory, directory=True)) != identity:
                _fail("directory_changed")
            if os.path.lexists(directory / "__init__.py"):
                _fail("unexpected_initializer")

    def _load(self):
        for name in tuple(sys.modules):
            if (name == "sentinel_daily_bootstrap" or name == "sentinel" or name.startswith("sentinel.") or
                    name == "tests" or name.startswith("tests.")):
                _fail("modules_preloaded")
        for entry in sys.path:
            if not entry:
                _fail("ambient_import_path")
            path = Path(entry)
            if ((path / "sentinel").exists() or (path / "sentinel_daily_bootstrap.py").exists() or
                    (path / "tests").exists()):
                _fail("ambient_import_path")
        self._path = tuple(sys.path)
        for name in _NAMESPACES:
            module = types.ModuleType(name)
            module.__path__ = ()
            module.__package__ = name
            module.__spec__ = importlib.util.spec_from_loader(name, loader=None, is_package=True)
            module.__spec__.submodule_search_locations = ()
            sys.modules[name] = module
            if "." in name:
                parent, child = name.rsplit(".", 1)
                setattr(sys.modules[parent], child, module)
            self._namespaces[name] = (module, module.__spec__)
        sys.modules[_PUBLIC_NAME] = self._bootstrap_module
        sys.modules["tests.windows"].adaptive_producer_bootstrap = self._bootstrap_module
        sys.meta_path.insert(0, self._finder)
        generation = importlib.import_module("sentinel.adaptive.daily_generation")
        self.manifest = generation.SourceManifest.capture(self.runtime_root)
        binding_module = importlib.import_module("sentinel.adaptive.capability_build")
        for name, _ in self._modules:
            importlib.import_module(name)
        self.modules = MappingProxyType({name: sys.modules[name] for name, _ in self._modules} |
                                       {_PUBLIC_NAME: self._bootstrap_module})
        self.source_binding = binding_module.SourceBinding(1, "canonical_runtime_fixture_inventory",
            str(self.runtime_root), str(self.producer_root), self.manifest.digest)
        self.build_source = binding_module.SourceBoundBuildSource(self.source_binding)
        self._original = (self.runtime_root, self.producer_root, self.manifest, self.source_binding,
                          self.build_source, self.modules)
        self._build = self.build_source()
        # The entry has not yet executed its post-bootstrap definitions. Pin its
        # actual complete module code now; callable identity checks concern only
        # members already defined at that boundary.
        self._ready = True
        self.assert_unchanged()
        return self

    def assert_unchanged(self):
        if (self is not _ORIGINAL or type(self) is not ProducerBootstrap or not self._ready or
                self._thread is not threading.current_thread() or self._pid != os.getpid() or
                any(current is not original for current, original in zip(
                    (self.runtime_root, self.producer_root, self.manifest, self.source_binding,
                     self.build_source, self.modules), self._original))):
            _fail("original_bootstrap_required")
        if tuple(sys.path) != self._path or not sys.meta_path or sys.meta_path[0] is not self._finder:
            _fail("import_path_changed")
        self._python.verify()
        if (self.entry != self._profile[0] or self._modules is not self._profile[1] or
                _PROFILES.get(self.entry) != self._profile[1:]):
            _fail("entry_profile_changed")
        for path, identity in self._roots.items():
            if _identity(_safe(path, directory=True)) != identity:
                _fail("root_changed")
        self._layout()
        for source in self._sources.values():
            source.verify()
        # __main__ continues running after bootstrap. Its original actual module
        # code and identity remain pinned; later definitions are checked against
        # that code rather than treating legitimate progress as module replacement.
        if (sys.modules.get("__main__") is not self._entry_module or
                self._entry_module.__spec__ is not self._entry_record.spec or
                self._entry_module.__file__ != str(self._entry_record.source.path)):
            _fail("entry_identity_changed")
        hashes = set()
        def collect(code):
            hashes.add(_code_key(code))
            for constant in code.co_consts:
                if type(constant) is types.CodeType:
                    collect(constant)
        collect(self._entry_record.code)
        for _, _, code in _members(self._entry_module):
            if code is not None and _code_key(code) not in hashes:
                _fail("entry_code_changed")
        self._bootstrap_record.verify()
        allowed = set(self._namespaces) | set(self.modules)
        if any((name == "tests" or name.startswith("tests.")) and name not in allowed for name in sys.modules):
            _fail("unreviewed_fixture_loaded")
        for name, (module, spec) in self._namespaces.items():
            if (sys.modules.get(name) is not module or module.__spec__ is not spec or
                    module.__path__ != () or spec.submodule_search_locations != ()):
                _fail("namespace_changed")
            if "." in name:
                parent, child = name.rsplit(".", 1)
                if getattr(sys.modules[parent], child, None) is not module:
                    _fail("namespace_changed")
        for name, module in self.modules.items():
            parent, child = name.rsplit(".", 1)
            if sys.modules.get(name) is not module or getattr(sys.modules[parent], child, None) is not module:
                _fail("module_identity_changed")
        for record in tuple(self._finder.loaded.values()):
            record.verify()
            if "." in record.name:
                parent, child = record.name.rsplit(".", 1)
                if getattr(sys.modules.get(parent), child, None) is not record.module:
                    _fail("module_identity_changed")
        generation = sys.modules["sentinel.adaptive.daily_generation"]
        generation.verify_import_provenance(self.manifest, self.runtime_root)
        generation.verify_loaded_source(self.manifest, self.runtime_root)
        if self.build_source() != self._build:
            _fail("build_changed")
        return self._build

    def source_pin(self):
        """Serializable consistency data only; never native/admission authority."""
        import hashlib
        build = self.assert_unchanged()
        return dict(schema_version=1, source_binding=self.source_binding.to_dict(),
                    build=dict(runtime_sha256=build.runtime_sha256, producer_sha256=build.producer_sha256),
                    python_sha256=hashlib.sha256(self._python.data).hexdigest())

    def verify_pin(self, value):
        import json
        if type(value) is not dict:
            _fail("source_pin_invalid")
        # Canonical JSON distinguishes bool from int and rejects non-finite
        # values; dict equality alone would accept True for schema version 1.
        try:
            observed = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError):
            _fail("source_pin_invalid")
        expected = json.dumps(self.source_pin(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        if observed != expected:
            _fail("source_pin_changed")
        return value


def bootstrap():
    """Run once directly in the real isolated console's module frame."""
    global _ORIGINAL
    if _ORIGINAL is not None:
        _fail("already_started")
    executable = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    if (not sys.flags.isolated or Path(sys.executable).resolve(strict=True) != executable or
            executable.name.casefold() in {"py.exe", "pyw.exe"}):
        _fail("isolated_base_python_required")
    frame = sys._getframe(1)
    try:
        owner = ProducerBootstrap(frame, _token=_BOOTSTRAP_CODE)
        _ORIGINAL = owner
        return owner._load()
    finally:
        del frame
