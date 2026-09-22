"""S3 bootstrap source boundary tests, without processes or Windows mutation."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.fixtures import adaptive_recovery_host as fixture
from tests.windows.adaptive_recovery_runner import CaseSpec, RawEvents, RecoveryRunUnavailable


class RecoveryBootstrapTests(unittest.TestCase):
    def test_host_path_must_equal_original_isolated_case(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            foreign = Path(directory) / "foreign"
            data.mkdir()
            foreign.mkdir()
            scope = {"data_directory": str(data), "journal_directory": str(data)}
            fixed = ["--journal-dir", str(data), "--guardian-epoch", "fixture"]
            fixture._assert_arguments_scope(["--data-dir", str(data), *fixed], scope)
            for args in (["--data-dir", str(foreign)],
                         ["--data-dir", str(data), "--data-dir=" + str(foreign)],
                         ["--data-dir", str(data), "--data=" + str(foreign)]):
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture._assert_arguments_scope([*args, *fixed], scope)
            for suffix in (["--journal-dir=" + str(foreign)], ["--journal=" + str(foreign)]):
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture._assert_arguments_scope(["--data-dir", str(data), *fixed, *suffix], scope)

    def test_unavailable_daily_provider_precedes_host_start(self):
        coverage_error = RuntimeError("original_daily_provider_missing")
        with patch.object(fixture, "load_case", return_value=(Path("test"), object(),
                {"data_directory": "test"})), patch.object(fixture, "_assert_arguments_scope"), \
                patch("tests.windows.adaptive_admission.require_continuous_admission", side_effect=coverage_error), \
                patch("sentinel.adaptive.guardian_host.main") as main:
            with self.assertRaisesRegex(RuntimeError, "original_daily_provider_missing"):
                fixture.run_role("test", "guardian", [])
            main.assert_not_called()

    def test_no_callback_or_boolean_can_replace_original_scope_bridge(self):
        for coverage in (None, SimpleNamespace(), SimpleNamespace(assert_spike_covered=Mock(return_value=True))):
            with patch.object(fixture, "load_case", return_value=(Path("test"), object(),
                    {"data_directory": "test"})), patch.object(fixture, "_assert_arguments_scope"), \
                    patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=coverage), \
                    patch("sentinel.adaptive.guardian_host.main") as main:
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture.run_role("test", "guardian", [])
                main.assert_not_called()

    def test_unarmed_or_different_fault_never_exits(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "intent_before", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture.os, "_exit") as exit_process:
                hooks.hit("intent_before")
                (path / "arm-fault").touch()
                hooks.hit("set_after_query_before")
                exit_process.assert_not_called()

    def test_armed_fault_requires_actual_native_scope_before_self_exit(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "intent_before", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "arm-fault").touch()
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture, "_tick", return_value=2), patch.object(fixture.os, "_exit") as exit_process:
                with self.assertRaisesRegex(RecoveryRunUnavailable, "owner_unbound"):
                    hooks.hit("intent_before")
                self.assertFalse(hooks.fired)
                exit_process.assert_not_called()

    def test_hook_restores_original_function_after_exception(self):
        original = lambda: None
        owner = SimpleNamespace(method=original)
        replacement = lambda: 4
        with self.assertRaisesRegex(RuntimeError, "fixture"):
            with fixture._replace(owner, "method", replacement):
                self.assertIs(owner.method, replacement)
                raise RuntimeError("fixture")
        self.assertIs(owner.method, original)

    def test_cleanup_hold_keeps_every_original_owner_and_does_not_retry_close(self):
        first, second, error = Mock(), Mock(), KeyboardInterrupt()
        hold = fixture.CleanupHold((first, second), error)
        self.assertIs(hold.owners[0], first)
        self.assertIs(hold.owners[1], second)
        self.assertIs(hold.error, error)
        first.close.assert_not_called()
        second.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
