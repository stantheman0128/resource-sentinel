"""Portable source-only producer bootstrap checks; no native acceptance.

Actual import observers, manifests and inventory readers execute in fresh -I
Python processes. Mutation tests use explicit minimal producer fixtures; the
source-only entry test copies the real reviewed entry and complete fixed module
closure. Neither activates a daily generation or invokes a native workload.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest

from sentinel.adaptive.daily_generation import REQUIRED_PATHS


_ROOT = Path(__file__).resolve().parents[1]
_ENTRY = r'''
import importlib
import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

mode, home = sys.argv[1:]
Path.home = classmethod(lambda cls: Path(home))
bootstrap_path = Path(__file__).with_name("adaptive_producer_bootstrap.py")
spec = importlib.util.spec_from_file_location("_sentinel_producer_bootstrap", bootstrap_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
bootstrap_code = compile(bootstrap_path.read_bytes(), str(bootstrap_path), "exec", dont_inherit=True)
if mode == "bootstrap_stacksize":
    bootstrap_code = bootstrap_code.replace(co_stacksize=bootstrap_code.co_stacksize + 1)
elif mode == "bootstrap_qualname":
    bootstrap_code = bootstrap_code.replace(co_qualname="different.bootstrap")
elif mode == "bootstrap_nested_metadata":
    nested = next(value for value in bootstrap_code.co_consts if type(value) is type(bootstrap_code))
    replaced = nested.replace(co_stacksize=nested.co_stacksize + 1)
    bootstrap_code = bootstrap_code.replace(co_consts=tuple(
        replaced if value is nested else value for value in bootstrap_code.co_consts))
exec(bootstrap_code, module.__dict__)
if mode == "code_inventory_unknown":
    module._CODE_ATTRIBUTES = module._CODE_ATTRIBUTES | {"co_future_field"}
elif mode == "code_inventory_missing":
    module._CODE_ATTRIBUTES = module._CODE_ATTRIBUTES - {"co_qualname"}
if mode in {"preloaded_runtime", "preloaded_fixture", "preloaded_namespace"}:
    name = {"preloaded_runtime": "sentinel", "preloaded_fixture": "tests.windows.adaptive_scope_launch",
            "preloaded_namespace": "tests"}[mode]
    sys.modules[name] = ModuleType(name)
elif mode == "ambient":
    sys.path.append(str(Path(home) / "ambient"))
elif mode == "self_changed":
    bootstrap_path.write_bytes(bootstrap_path.read_bytes() + b"\nBOOTSTRAP_DRIFT = True\n")
elif mode == "redirected":
    old_lstat = Path.lstat
    redirected = Path(__file__).parents[1]
    def fixture_lstat(self, *args, **kwargs):
        if self == redirected:
            return SimpleNamespace(st_mode=0o40755, st_file_attributes=0x400)
        return old_lstat(self, *args, **kwargs)
    Path.lstat = fixture_lstat
try:
    if mode == "indirect":
        def invoke():
            return module.bootstrap()
        owner = invoke()
    else:
        owner = module.bootstrap()
    launch = owner.modules["tests.windows.adaptive_scope_launch"]
    before = owner.assert_unchanged()
    if mode == "identity":
        sys.modules["tests.windows.adaptive_scope_launch"] = ModuleType("tests.windows.adaptive_scope_launch")
    elif mode == "parent_alias":
        sys.modules["tests.windows"].adaptive_scope_launch = ModuleType("replacement")
    elif mode == "runtime_parent_alias":
        sys.modules["sentinel.adaptive"].daily_generation = ModuleType("replacement")
    elif mode.startswith("imported_"):
        provider = owner.modules["tests.windows.adaptive_s1_provider"]
        name = mode.removeprefix("imported_")
        setattr(provider, name, object())
    elif mode == "custody_state":
        provider = owner.modules["tests.windows.adaptive_s1_provider"]
        original = SimpleNamespace(closed=False)
        provider._CASES.append(original)
        provider._OWNERS[id(original)] = original
        original.closed = True
    elif mode == "function":
        exec("def replacement():\n    return 'changed'\n", launch.__dict__)
        launch.original = launch.replacement
    elif mode == "function_code":
        launch.original.__code__ = (lambda: "changed").__code__
    elif mode == "entry_function":
        exec("def added():\n    return 'not original entry code'\n")
    elif mode in {"entry_stacksize", "entry_qualname", "entry_nested_metadata"}:
        def entry_owned():
            def child():
                return 42
            return child
        original = entry_owned.__code__
        if mode == "entry_stacksize":
            entry_owned.__code__ = original.replace(co_stacksize=original.co_stacksize + 1)
        elif mode == "entry_qualname":
            entry_owned.__code__ = original.replace(co_qualname="different.entry_owned")
        else:
            nested = next(value for value in original.co_consts if type(value) is type(original))
            replaced = nested.replace(co_qualname="different.child")
            entry_owned.__code__ = original.replace(co_consts=tuple(
                replaced if value is nested else value for value in original.co_consts))
    elif mode == "structural_schema_parity":
        import struct
        generation = sys.modules["sentinel.adaptive.daily_generation"]
        observer = sys.modules["sentinel_daily_bootstrap"]
        first, second = (struct.unpack(">d", bytes.fromhex("7ff8000000000001"))[0] for _ in range(2))
        one, two = frozenset((first,)), frozenset((first, second))
        assert len(two) == 2
        assert module._constant_key(one) != module._constant_key(two)
        for value in (None, Ellipsis, True, 1, "text", b"text", -0.0, first, complex(1, -0.0), (one, two)):
            assert module._constant_key(value) == generation._constant_key(value) == observer._constant_key(value)
        assert module._code_key(bootstrap_code) == generation._code_key(bootstrap_code) == observer._code_key(bootstrap_code)
    elif mode == "extra_module":
        sys.modules["tests.windows.not_reviewed"] = ModuleType("tests.windows.not_reviewed")
    elif mode == "old_runner_import":
        importlib.import_module("tests.windows.adaptive_execution")
    elif mode == "namespace_path":
        sys.modules["tests.windows"].__path__ = [str(Path(__file__).parent)]
    elif mode == "namespace_alias":
        sys.modules["tests"].windows = ModuleType("replacement")
    elif mode == "finder":
        sys.meta_path.remove(owner._finder)
    elif mode == "sys_path":
        sys.path.append(str(owner.producer_root))
    elif mode == "source":
        source = Path(launch.__file__)
        source.write_bytes(source.read_bytes() + b"\n# drift\n")
    elif mode == "source_replaced":
        source = Path(launch.__file__)
        raw = source.read_bytes()
        source.rename(source.with_suffix(".previous"))
        source.write_bytes(raw)
    elif mode == "runtime":
        source = owner.runtime_root / "sentinel/adaptive/contracts.py"
        source.write_bytes(source.read_bytes() + b"\n# drift\n")
    elif mode == "inventory":
        (owner.producer_root / "tests/benchmarks/new.py").write_text("# additional source\n")
    elif mode == "root_replaced":
        import shutil
        previous = owner.producer_root.with_name("previous")
        owner.producer_root.rename(previous)
        shutil.copytree(previous, owner.producer_root)
    elif mode == "initializer_after":
        (owner.producer_root / "tests/__init__.py").write_text("# unexpected\n")
    elif mode == "binding_replaced":
        from dataclasses import replace
        owner.source_binding = replace(owner.source_binding)
    elif mode == "bootstrap_alias":
        sys.modules["tests.windows.adaptive_producer_bootstrap"] = ModuleType("replacement")
    elif mode == "repeat":
        module.bootstrap()
    elif mode == "fixture_reload":
        importlib.reload(launch)
    elif mode == "runtime_loaded_code":
        target = sys.modules["sentinel.adaptive.contracts"]
        target.strict_json_loads.__code__ = (lambda value: value).__code__
    elif mode.startswith("handle_drift_"):
        field = mode.removeprefix("handle_drift_")
        original_fstat = module.os.fstat
        count = 0
        def drifting_fstat(fd):
            global count
            count += 1
            original = original_fstat(fd)
            names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns", "st_ctime_ns")
            value = {name: getattr(original, name, None) for name in names}
            if count % 2 == 0:
                value[field] += 1
            return SimpleNamespace(**value)
        module.os.fstat = drifting_fstat
    elif mode == "path_handle_ctime_semantics":
        original_fstat = module.os.fstat
        def different_ctime(fd):
            original = original_fstat(fd)
            names = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns", "st_ctime_ns")
            value = {name: getattr(original, name, None) for name in names}
            value["st_ctime_ns"] += 987654321
            return SimpleNamespace(**value)
        module.os.fstat = different_ctime
        # Explicit metadata fixture: different ctime meaning is accepted for a
        # fresh source, but its original handle signature is then retained.
        pinned = module._Source(Path(launch.__file__))
        pinned.verify()
        module.os.fstat = original_fstat
    after = owner.assert_unchanged()
    assert before == after
    assert owner.modules["tests.windows.adaptive_s1_provider"].ScopeCommand is launch.ScopeCommand
    assert owner.modules["tests.windows.adaptive_s1_measurements"].PROVIDER is owner.modules["tests.windows.adaptive_s1_provider"]
    assert sys.modules["tests.windows.adaptive_producer_bootstrap"] is module
    assert str(owner.producer_root) not in sys.path
    assert str(owner.runtime_root) not in sys.path
    outcome = {"accepted": True, "initializer": launch.INITIALIZER,
               "runtime_initializer": sys.modules["sentinel.adaptive"].RUNTIME_INITIALIZER,
               "digest": owner.source_binding.source_digest, "modules": sorted(owner.modules),
               "namespace_paths": [list(sys.modules[name].__path__) for name in module._NAMESPACES]}
except Exception as error:
    outcome = {"accepted": False, "reason": str(error), "type": type(error).__name__}
outcome["observer_installed"] = getattr(sys.modules.get("sentinel_daily_bootstrap"), "_OBSERVER", None) is not None
print(json.dumps(outcome, sort_keys=True))
'''


class ProducerBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sentinel-producer-bootstrap-")
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.runtime = self.home / "Projects/resource-sentinel"
        self.producer = self.home / "reviewed"
        for relative in REQUIRED_PATHS:
            path = self.runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"# isolated source fixture\n")
        # Keep the actual full import graph and original provenance observer.
        # Only the outer path is an isolated temporary canonical-home fixture.
        for source in (_ROOT / "sentinel").rglob("*.py"):
            target = self.runtime / source.relative_to(_ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        (self.runtime / "sentinel_daily_bootstrap.py").write_bytes((_ROOT / "sentinel_daily_bootstrap.py").read_bytes())
        adaptive = self.runtime / "sentinel/adaptive/__init__.py"
        adaptive.write_bytes(adaptive.read_bytes() + b"\nRUNTIME_INITIALIZER = 'NEW'\n")
        for name in ("windows", "fixtures", "benchmarks"):
            (self.producer / "tests" / name).mkdir(parents=True)
        self.entry = self.producer / "tests/windows/run_adaptive_s1.py"
        self.entry.write_text(_ENTRY, encoding="utf-8")
        self.bootstrap_file = self.producer / "tests/windows/adaptive_producer_bootstrap.py"
        self.bootstrap_file.write_bytes((_ROOT / "tests/windows/adaptive_producer_bootstrap.py").read_bytes())
        self.launch = self.producer / "tests/windows/adaptive_scope_launch.py"
        self.launch.write_text("INITIALIZER = 'NEW'\nclass ScopeCommand: pass\ndef original():\n    return 'original'\n", encoding="utf-8")
        (self.producer / "tests/windows/adaptive_s1_provider.py").write_text(
            "from tests.windows.adaptive_scope_launch import ScopeCommand\n"
            "from sentinel.coordinator import Coordinator\n"
            "from sentinel.adaptive.experiment_demand import DailyExperimentDemand\n"
            "from sentinel.adaptive.experiment_scope import ExperimentNativeScope\n"
            "from sentinel.adaptive import daily_generation\n"
            "from sentinel.adaptive.sampler import profile_revision\n"
            "_CASES = []\n_OWNERS = {}\n", encoding="utf-8")
        (self.producer / "tests/windows/adaptive_capability_runner.py").write_text(
            "from sentinel.adaptive import capability_evidence as evidence\n", encoding="utf-8")
        (self.producer / "tests/windows/adaptive_s1_measurements.py").write_text(
            "from tests.windows import adaptive_s1_provider as PROVIDER\n"
            "from tests.windows.adaptive_capability_runner import evidence\n", encoding="utf-8")
        for relative in ("tests/windows/adaptive_scope_wrapper.py", "tests/fixtures/adaptive_scope_cpu_worker.py"):
            (self.producer / relative).write_text("# separately pinned subprocess fixture, not executed\n", encoding="utf-8")
        self.python = str(Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True))

    def run_bootstrap(self, mode="normal"):
        result = subprocess.run([self.python, "-I", str(self.entry), mode, str(self.home)],
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def refusal(self, mode, expected):
        outcome = self.run_bootstrap(mode)
        self.assertFalse(outcome["accepted"], outcome)
        self.assertIn(expected, outcome["reason"], outcome)
        return outcome

    def stale_cache(self, path):
        new = path.read_bytes()
        old = new.replace(b"'NEW'", b"'OLD'")
        self.assertNotEqual(old, new)
        timestamp = 1_690_000_000_000_000_000
        path.write_bytes(old)
        os.utime(path, ns=(timestamp, timestamp))
        cached = Path(py_compile.compile(str(path), doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
        path.write_bytes(new)
        os.utime(path, ns=(timestamp, timestamp))
        self.assertTrue(cached.is_file())

    def test_actual_source_observer_and_restricted_identity_closure(self):
        outcome = self.run_bootstrap()
        self.assertTrue(outcome["accepted"], outcome)
        self.assertTrue(outcome["observer_installed"])
        self.assertEqual(len(outcome["modules"]), 5)
        self.assertEqual(outcome["namespace_paths"], [[], [], [], []])
        self.assertEqual(len(outcome["digest"]), 64)

    def test_real_entry_and_complete_reviewed_fixture_closure_check_source_only(self):
        # These are the actual reviewed bytes, not the small mutation fixtures
        # installed by setUp. Copying into this test's temporary source tree
        # neither deploys files nor alters the actual canonical runtime.
        closure = (
            "tests/windows/run_adaptive_s1.py",
            "tests/windows/adaptive_producer_bootstrap.py",
            "tests/windows/adaptive_scope_launch.py",
            "tests/windows/adaptive_s1_provider.py",
            "tests/windows/adaptive_capability_runner.py",
            "tests/windows/adaptive_s1_measurements.py",
            "tests/windows/adaptive_scope_wrapper.py",
            "tests/fixtures/adaptive_scope_cpu_worker.py",
        )
        for relative in closure:
            (self.producer / relative).write_bytes((_ROOT / relative).read_bytes())
        environment = dict(os.environ)
        environment["USERPROFILE"] = str(self.home)
        environment["HOME"] = str(self.home)
        output = self.home / "unused-measurement-output"
        before = {path.relative_to(self.home) for path in self.home.rglob("*")}
        result = subprocess.run([self.python, "-I", str(self.entry), "--check-source",
            "--directory", str(output)], env=environment, cwd=self.home,
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        outcome = json.loads(result.stdout)
        self.assertEqual(set(outcome), {"status", "promotion", "source_digest",
                                       "runtime_sha256", "producer_sha256"})
        self.assertEqual(outcome["status"], "source_verified")
        self.assertIs(outcome["promotion"], False)
        for key in ("source_digest", "runtime_sha256", "producer_sha256"):
            self.assertRegex(outcome[key], r"\A[a-f0-9]{64}\Z")
        self.assertFalse(output.exists(), "source-only entry must not create an evidence artifact directory")
        self.assertFalse((self.home / ".resource-sentinel").exists(), "source-only entry must not create daily state")
        self.assertEqual({path.relative_to(self.home) for path in self.home.rglob("*")}, before,
                         "source-only entry must create no artifact, ledger, cache or temporary directory")

    def test_fixture_and_runtime_execute_source_despite_stale_pyc(self):
        self.stale_cache(self.launch)
        self.stale_cache(self.runtime / "sentinel/adaptive/__init__.py")
        outcome = self.run_bootstrap()
        self.assertTrue(outcome["accepted"], outcome)
        self.assertEqual(outcome["initializer"], "NEW")
        self.assertEqual(outcome["runtime_initializer"], "NEW")

    def test_preloaded_runtime_fixture_and_namespace_are_refused(self):
        for mode in ("preloaded_runtime", "preloaded_fixture", "preloaded_namespace"):
            with self.subTest(mode=mode):
                self.refusal(mode, "modules_preloaded")

    def test_ambient_runtime_path_is_refused_before_import(self):
        (self.home / "ambient/sentinel").mkdir(parents=True)
        outcome = self.refusal("ambient", "ambient_import_path")
        self.assertFalse(outcome["observer_installed"])

    def test_all_unreviewed_namespace_initializers_refused(self):
        for relative in ("tests", "tests/windows", "tests/fixtures", "tests/benchmarks"):
            path = self.producer / relative / "__init__.py"
            path.write_text("raise AssertionError('must not execute initializer')\n")
            with self.subTest(relative=relative):
                self.refusal("normal", "unexpected_initializer")
            path.unlink()

    def test_redirected_directory_refused_before_import(self):
        self.refusal("redirected", "redirected_path")

    def test_missing_fixed_measurements_refused_before_import(self):
        (self.producer / "tests/windows/adaptive_s1_measurements.py").unlink()
        outcome = self.run_bootstrap()
        self.assertFalse(outcome["accepted"], outcome)
        self.assertEqual(outcome["type"], "FileNotFoundError")
        self.assertFalse(outcome["observer_installed"])

    def test_executed_bootstrap_and_entry_boundary_are_pinned(self):
        self.refusal("indirect", "original_entry_required")
        self.refusal("self_changed", "executed_code_changed")

    def test_bootstrap_module_and_nested_metadata_are_pinned(self):
        for mode in ("bootstrap_stacksize", "bootstrap_qualname", "bootstrap_nested_metadata"):
            with self.subTest(mode=mode):
                self.refusal(mode, "executed_code_changed")

    def test_entry_function_and_nested_metadata_are_pinned(self):
        for mode in ("entry_stacksize", "entry_qualname", "entry_nested_metadata"):
            with self.subTest(mode=mode):
                self.refusal(mode, "entry_code_changed")

    def test_code_attribute_inventory_requires_exact_reviewed_fields(self):
        for mode in ("code_inventory_unknown", "code_inventory_missing"):
            with self.subTest(mode=mode):
                self.refusal(mode, "code_unverified")

    def test_independent_stdlib_bootstrap_keys_match_runtime_schema(self):
        outcome = self.run_bootstrap("structural_schema_parity")
        self.assertTrue(outcome["accepted"], outcome)

    def test_loaded_module_and_parent_alias_replacement_refused(self):
        for mode in ("identity", "parent_alias", "bootstrap_alias", "runtime_parent_alias"):
            with self.subTest(mode=mode):
                self.refusal(mode, "module_identity_changed")

    def test_imported_authority_classes_module_and_function_bindings_are_pinned(self):
        for name in ("ScopeCommand", "Coordinator", "DailyExperimentDemand", "ExperimentNativeScope",
                     "daily_generation", "profile_revision"):
            with self.subTest(name=name):
                self.refusal("imported_" + name, "module_identity_changed")

    def test_ordinary_original_custody_state_remains_mutable(self):
        outcome = self.run_bootstrap("custody_state")
        self.assertTrue(outcome["accepted"], outcome)

    def test_path_and_handle_ctime_use_separate_stable_signatures(self):
        outcome = self.run_bootstrap("path_handle_ctime_semantics")
        self.assertTrue(outcome["accepted"], outcome)

    def test_handle_identity_timestamp_or_size_drift_still_refuses(self):
        for field in ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"):
            with self.subTest(field=field):
                self.refusal("handle_drift_" + field, "source_changed")

    def test_function_object_or_code_replacement_refused(self):
        for mode in ("function", "function_code"):
            with self.subTest(mode=mode):
                self.refusal(mode, "module_identity_changed")

    def test_entry_function_outside_original_module_code_refused(self):
        self.refusal("entry_function", "entry_code_changed")

    def test_unreviewed_fixture_and_legacy_runner_dependency_refused(self):
        self.refusal("extra_module", "unreviewed_fixture_loaded")
        self.refusal("old_runner_import", "unreviewed_fixture")

    def test_namespace_search_path_and_finder_changes_refused(self):
        self.refusal("namespace_path", "namespace_changed")
        self.refusal("namespace_alias", "namespace_changed")
        self.refusal("finder", "import_path_changed")
        self.refusal("sys_path", "import_path_changed")

    def test_source_content_and_identical_file_replacement_refused(self):
        original = self.launch.read_bytes()
        self.refusal("source", "source_changed")
        self.launch.write_bytes(original)
        self.refusal("source_replaced", "source_changed")

    def test_runtime_change_and_loaded_code_change_refused(self):
        self.refusal("runtime_loaded_code", "module_identity_changed")
        self.refusal("runtime", "source_changed")

    def test_complete_producer_inventory_addition_refused(self):
        self.refusal("inventory", "capability_build_inventory_changed")

    def test_identical_producer_root_replacement_refused(self):
        self.refusal("root_replaced", "root_changed")

    def test_initializer_added_after_bootstrap_refused(self):
        self.refusal("initializer_after", "unexpected_initializer")

    def test_copied_binding_cannot_replace_original_reader_binding(self):
        self.refusal("binding_replaced", "original_bootstrap_required")

    def test_bootstrap_and_fixture_reexecution_refused(self):
        self.refusal("repeat", "already_started")
        self.refusal("fixture_reload", "module_reexecution")

    def test_bootstrap_has_no_source_or_hash_override_parameters(self):
        # Syntax is inspected without importing a second live bootstrap owner.
        import ast
        tree = ast.parse(self.bootstrap_file.read_text(encoding="utf-8"))
        function = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "bootstrap")
        self.assertEqual(function.args.args, [])
        self.assertEqual(function.args.kwonlyargs, [])
        self.assertIsNone(function.args.vararg)
        self.assertIsNone(function.args.kwarg)


if __name__ == "__main__":
    unittest.main()
