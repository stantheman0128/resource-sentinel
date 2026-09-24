"""External entry custody tests with explicit source-only/native-owner seams."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.windows import run_adaptive_s1 as entry


class S1EntryTests(unittest.TestCase):
    def setUp(self):
        self.addCleanup(entry._FAILURES.clear)
        entry._FAILURES.clear()
        self.addCleanup(setattr, entry, "_RUN", None)

    def test_help_works_in_isolated_interpreter_before_bootstrap_or_native_import(self):
        result = subprocess.run([sys._base_executable, "-I", entry.__file__, "--help"],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--directory", result.stdout)
        self.assertNotIn("bootstrap_failed", result.stdout)

    def test_checked_bootstrap_executes_source_and_retains_module(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "adaptive_producer_bootstrap.py"
            source.write_text("MARKER = 'source'\n", encoding="utf-8")
            old = sys.modules.pop("_sentinel_producer_bootstrap", None)
            try:
                with patch.object(entry, "__file__", str(root / "run_adaptive_s1.py")):
                    module = entry._load_bootstrap()
                    self.assertEqual(module.MARKER, "source")
                    self.assertIs(sys.modules["_sentinel_producer_bootstrap"], module)
                    with self.assertRaisesRegex(RuntimeError, "preloaded"):
                        entry._load_bootstrap()
            finally:
                sys.modules.pop("_sentinel_producer_bootstrap", None)
                if old is not None:
                    sys.modules["_sentinel_producer_bootstrap"] = old

    def test_oversized_bootstrap_refuses_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "adaptive_producer_bootstrap.py").write_bytes(b"x" * 20)
            with patch.object(entry, "__file__", str(root / "run_adaptive_s1.py")), \
                    patch.object(entry, "_MAX_BOOTSTRAP_BYTES", 10), \
                    self.assertRaisesRegex(RuntimeError, "file_invalid"):
                entry._load_bootstrap()

    def run_fixture(self, *, constructor_error=False, recovery_interrupt=False, output_fails=False):
        events, provider = [], object()
        profile = entry._read_profile(Path(__file__).resolve().parents[1] / "config/adaptive.example.json")
        class Run:
            def __init__(self, directory, profile, *, bootstrap):
                events.append("construct")
                self.assert_original = entry._RUN is self
                self.profile = profile
                self._s1_provider = provider
                self._s1_initialized = not constructor_error
                if constructor_error:
                    raise OSError("private constructor detail")
            def run_s1(self):
                events.append("measure")
                raise KeyboardInterrupt("measurement interrupted")
        runner = SimpleNamespace(NativeEvidenceRun=Run,
            error_evidence=lambda error, **kwargs: [{"reason": "test_failure"}])
        bootstrap = SimpleNamespace(modules={"tests.windows.adaptive_capability_runner": runner})
        counts = []
        def recover(run, actual_runner, primary):
            counts.append((run, entry._RUN, actual_runner, primary))
            if recovery_interrupt and len(counts) == 1:
                raise KeyboardInterrupt()
            return len(counts) < 3
        with patch.object(entry, "_recover", side_effect=recover), \
                patch.object(entry, "_emit", return_value=not output_fails), \
                patch.object(entry.time, "sleep"):
            result = entry._run(bootstrap, Path("C:/isolated-evidence"), profile)
        self.assertEqual(result, 1)
        self.assertTrue(entry._RUN.assert_original)
        self.assertEqual(events, ["construct"] if constructor_error else ["construct", "measure"])
        self.assertEqual(len(counts), 3)
        self.assertIs(entry._RUN.profile, profile)
        self.assertTrue(all(actual is entry._RUN and original is actual and actual_runner is runner
            for actual, original, actual_runner, _ in counts))
        self.assertIs(entry._RUN._s1_provider, provider)

    def test_profile_reads_actual_example_without_enabling_control_or_writing_it(self):
        path = Path(__file__).resolve().parents[1] / "config/adaptive.example.json"
        original = path.read_bytes()
        profile = entry._read_profile(path)
        self.assertEqual(profile.mode.value, "off")
        self.assertEqual(profile.max_enrolled_jobs, 10)
        self.assertEqual(profile.max_active_caps, 1)
        self.assertEqual(path.read_bytes(), original)

    def test_profile_rejects_enforce_unknown_fields_and_oversized_input(self):
        from sentinel.adaptive.contracts import ContractViolation
        original = json.loads((Path(__file__).resolve().parents[1] /
            "config/adaptive.example.json").read_text("utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "profile.json"
            for label, changed in (("enforce", dict(original, mode="enforce")),
                    ("extra", dict(original, unknown=True))):
                path.write_text(json.dumps(changed), encoding="utf-8")
                with self.subTest(label=label), self.assertRaises(ContractViolation):
                    entry._read_profile(path)
            path.write_bytes(b" " * 65537)
            with self.assertRaisesRegex(RuntimeError, "file_invalid"):
                entry._read_profile(path)

    def test_constructor_failure_keeps_original_run_before_handoff(self):
        self.run_fixture(constructor_error=True)

    def test_interrupted_measurement_recovers_original_without_rerunning(self):
        self.run_fixture(recovery_interrupt=True)

    def test_log_output_failure_does_not_drop_original_recovery(self):
        self.run_fixture(output_fails=True)

    def test_recover_calls_only_original_provider_tick_and_rechecks_custody(self):
        provider = SimpleNamespace(recover_once=Mock())
        run = SimpleNamespace(_s1_provider=provider, _s1_initialized=True)
        runner = SimpleNamespace(custody_pending=Mock(side_effect=[True, False]))
        with patch.object(entry, "_context_cleanup", return_value=False):
            self.assertFalse(entry._recover(run, runner, RuntimeError()))
        provider.recover_once.assert_called_once_with()
        self.assertEqual(runner.custody_pending.call_count, 2)

    def test_failed_custody_inspection_keeps_original_pending(self):
        provider = SimpleNamespace(recover_once=Mock())
        run = SimpleNamespace(_s1_provider=provider, _s1_initialized=True)
        runner = SimpleNamespace(custody_pending=Mock(side_effect=RuntimeError("unknown")))
        with patch.object(entry, "_context_cleanup", return_value=False):
            self.assertTrue(entry._recover(run, runner, RuntimeError()))
        provider.recover_once.assert_not_called()

    def test_partial_source_only_provider_constructor_never_enters_recovery_api(self):
        run = SimpleNamespace(_s1_provider=object(), _s1_initialized=False)
        runner = SimpleNamespace(custody_pending=Mock())
        with patch.object(entry, "_context_cleanup", return_value=False):
            self.assertFalse(entry._recover(run, runner, RuntimeError()))
        runner.custody_pending.assert_not_called()

    def test_context_cleanup_uses_retained_reader_not_replacement(self):
        current = SimpleNamespace(close=Mock())
        original = SimpleNamespace(_current=current, _pending_buffer=None, _failure=None)
        replacement = SimpleNamespace(_current=SimpleNamespace(close=Mock()))
        run = SimpleNamespace(context_source=replacement, _source_original=(None, None, None, original, None))
        self.assertFalse(entry._context_cleanup(run, RuntimeError()))
        current.close.assert_called_once_with()
        replacement._current.close.assert_not_called()
        self.assertIsNone(original._current)

    def test_unknown_context_buffer_stays_owned_without_reacquiring_or_freeing(self):
        buffer = object()
        reader = SimpleNamespace(_current=None, _pending_buffer=buffer, _failure=None)
        run = SimpleNamespace(context_source=reader)
        self.assertTrue(entry._context_cleanup(run, RuntimeError()))
        self.assertIs(reader._pending_buffer, buffer)

    def test_context_identity_cleanup_failure_remains_pending(self):
        owner = SimpleNamespace(close=Mock(side_effect=OSError("unknown close")))
        reader = SimpleNamespace(_current=owner, _pending_buffer=None, _failure=None)
        self.assertTrue(entry._context_cleanup(SimpleNamespace(context_source=reader), RuntimeError()))
        self.assertIs(reader._current, owner)


if __name__ == "__main__":
    unittest.main()
