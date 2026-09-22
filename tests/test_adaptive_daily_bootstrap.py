"""Complete executed-code provenance; fixtures never install a global audit hook."""
from importlib.machinery import ModuleSpec
from pathlib import Path
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch

import sentinel_daily_bootstrap as bootstrap


class DailyBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "sentinel").mkdir()
        self.initial = compile("# package fixture\n", str(self.root / "sentinel/__init__.py"), "exec")
        self.observer = bootstrap.ImportObserver(self.root, initial_code=self.initial)
        self.observer.audit("resource_sentinel.import_provenance", (self.observer._probe,))
        self.sources = {"sentinel_daily_bootstrap.py": Path(bootstrap.__file__).read_bytes()}

    def module(self, source, *, name="sentinel.example", observe=True):
        path = self.root / (name.replace(".", "/") + ".py")
        path.write_text(source)
        module = ModuleType(name)
        module.__file__ = str(path)
        module.__spec__ = ModuleSpec(name, loader=None, origin=str(path))
        module.__spec__._initializing = False
        code = compile(source, str(path), "exec", dont_inherit=True)
        if observe:
            self.observer.audit("exec", (code,))
        exec(code, module.__dict__)
        self.sources[path.relative_to(self.root).as_posix()] = source.encode()
        return module

    def verify(self, module):
        return self.observer.assert_modules(self.root, self.sources, modules={module.__name__: module})

    def test_actual_complete_module_code_matches(self):
        module = self.module("POLICY = 'current'\ndef admit():\n    return POLICY\n")
        self.assertIsNone(self.verify(module))

    def test_changed_global_initializer_cannot_hide_behind_same_function_code(self):
        module = self.module("POLICY = 'old'\ndef admit():\n    return POLICY\n")
        self.sources["sentinel/example.py"] = b"POLICY = 'new'\ndef admit():\n    return POLICY\n"
        self.assertEqual(module.admit(), "old")
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "executed_module_generation_mismatch"):
            self.verify(module)

    def test_changed_decorator_execution_is_detected(self):
        source = "def choose(value):\n    return lambda function: (lambda: value)\n@choose('old')\ndef admit():\n    return 'body'\n"
        module = self.module(source)
        self.sources["sentinel/example.py"] = source.replace("choose('old')", "choose('new')").encode()
        self.assertEqual(module.admit(), "old")
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "generation_mismatch"):
            self.verify(module)

    def test_already_loaded_unobserved_module_is_refused(self):
        module = self.module("VALUE = 1\n", observe=False)
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "unobserved"):
            self.verify(module)

    def test_half_imported_module_is_refused(self):
        module = self.module("VALUE = 1\n")
        module.__spec__._initializing = True
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "completion_unverified"):
            self.verify(module)

    def test_observer_installation_probe_required(self):
        module = self.module("VALUE = 1\n")
        self.observer._probe_seen = False
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "provenance_unavailable"):
            self.verify(module)

    def test_different_module_reexecution_is_sticky_unknown(self):
        module = self.module("VALUE = 1\n")
        self.observer.audit("exec", (compile("VALUE = 2\n", module.__file__, "exec"),))
        self.observer.audit("exec", (compile("VALUE = 1\n", module.__file__, "exec"),))
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "provenance_unavailable"):
            self.verify(module)

    def test_same_code_reexecution_does_not_change_generation(self):
        module = self.module("VALUE = 1\n")
        self.observer.audit("exec", (compile("VALUE = 1\n", module.__file__, "exec"),))
        self.assertIsNone(self.verify(module))

    def test_bootstrap_source_itself_is_pinned(self):
        module = self.module("VALUE = 1\n")
        self.sources["sentinel_daily_bootstrap.py"] = b"# different bootstrap\n"
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "bootstrap_generation_mismatch"):
            self.verify(module)

    def test_code_inventory_bound_refuses_unknown_coverage(self):
        module = self.module("VALUE = 1\n")
        with patch.object(bootstrap, "MAX_MODULES", 3):
            self.module("VALUE = 2\n", name="sentinel.second")
        with self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "provenance_unavailable"):
            self.verify(module)

    def test_missing_original_observer_cannot_be_replaced_by_file_data(self):
        with patch.object(bootstrap, "_OBSERVER", None), \
                self.assertRaisesRegex(bootstrap.ImportProvenanceUnavailable, "not_installed"):
            bootstrap.assert_import_provenance(self.root, self.sources)

    def test_no_import_or_native_writes_in_unrelated_audit_events(self):
        before = dict(self.observer._code)
        for name in ("open", "sqlite3.connect", "subprocess.Popen", "compile"):
            self.observer.audit(name, ("private data",))
        self.assertEqual(before, self.observer._code)


if __name__ == "__main__":
    unittest.main()
