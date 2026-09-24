"""Portable fault models for S2 wrapper custody; not native launch evidence."""
from contextlib import nullcontext
import base64
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import native_launcher, wrapper_host
from tests.fixtures import adaptive_launch_producer_child as fixture


class WrapperStdinSelectorTests(unittest.TestCase):
    def test_selector_uses_current_restored_fd_instead_of_original_closed_value(self):
        kernel = SimpleNamespace(SetStdHandle=Mock(return_value=1), GetStdHandle=Mock(return_value=222))
        descriptor = SimpleNamespace(get_osfhandle=Mock(return_value=222))
        fixture._WrapperStdinSelector(kernel, descriptor, "stdin")()
        descriptor.get_osfhandle.assert_called_once_with(0)
        kernel.SetStdHandle.assert_called_once_with("stdin", 222)
        kernel.GetStdHandle.assert_called_once_with("stdin")

    def test_invalid_descriptor_or_wrong_selector_is_not_positive_restoration(self):
        kernel = SimpleNamespace(SetStdHandle=Mock(return_value=1), GetStdHandle=Mock(return_value=111))
        descriptor = SimpleNamespace(get_osfhandle=Mock(return_value=-1))
        restore = fixture._WrapperStdinSelector(kernel, descriptor, "stdin")
        with self.assertRaisesRegex(RuntimeError, "descriptor_unverified"):
            restore()
        kernel.SetStdHandle.assert_not_called()
        descriptor.get_osfhandle.return_value = 222
        with self.assertRaisesRegex(RuntimeError, "restore_unverified"):
            restore()


class WrapperCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.raw = {"infrastructure_failure": None}
        self.owner = fixture._WrapperCustody(self.directory, self.raw)

    def attach_host(self, receipt=None, *, closed=True):
        host = SimpleNamespace(launcher=SimpleNamespace(_closed=closed),
            _construction_unknown=None, _note_recovery_error=Mock(),
            settle_release=Mock(return_value=receipt))
        self.owner.host, self.owner.constructed = host, True
        return host

    def test_partial_constructor_is_registered_before_its_first_effect(self):
        owner = self.owner
        original = []
        class FailingHost:
            def __init__(self):
                original.append(self)
                self.partial_resource = object()
                if owner.host is not self:
                    raise AssertionError("original was not registered")
                raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            owner.construct(FailingHost)
        self.assertIs(owner.host, original[0])
        self.assertFalse(owner.constructed)
        self.assertFalse(owner.step_host())
        with self.assertRaisesRegex(RuntimeError, "already_attempted"):
            owner.construct(FailingHost)
        self.assertEqual(len(original), 1)

    def test_post_launch_observation_failures_transfer_the_exact_native_owner(self):
        for error in (OSError("artifact unavailable"), KeyboardInterrupt(), MemoryError()):
            with self.subTest(error=type(error).__name__):
                owner = fixture._WrapperCustody(self.directory, {"infrastructure_failure": None})
                process = SimpleNamespace(_closed=False)
                native = SimpleNamespace(launch_in_job=Mock(return_value=process),
                                         LaunchOutcomeUnknown=native_launcher.LaunchOutcomeUnknown)
                with self.assertRaises(native_launcher.LaunchOutcomeUnknown) as raised:
                    owner.observe_launch(native, "original job", "application", "command",
                                         Mock(side_effect=error), stdin_handle=11)
                self.assertIs(raised.exception.process, process)
                self.assertIs(raised.exception.native_launch_owner, process)
                self.assertIs(raised.exception.cause, error)
                self.assertIs(owner.native_process, process)
                native.launch_in_job.assert_called_once_with("original job", "application", "command", stdin_handle=11)
                with self.assertRaisesRegex(RuntimeError, "already_attempted"):
                    owner.observe_launch(native, "original job", "application", "command", Mock())
                self.assertEqual(native.launch_in_job.call_count, 1)

    def test_native_partial_failure_is_preserved_without_replacing_its_owner(self):
        process = SimpleNamespace(_closed=False)
        error = native_launcher.LaunchOutcomeUnknown(process, OSError("native cleanup pending"))
        native = SimpleNamespace(launch_in_job=Mock(side_effect=error),
                                 LaunchOutcomeUnknown=native_launcher.LaunchOutcomeUnknown)
        with self.assertRaises(native_launcher.LaunchOutcomeUnknown) as raised:
            self.owner.observe_launch(native, "job", "application", "command", Mock())
        self.assertIs(raised.exception, error)
        self.assertIs(self.owner.native_error, error)
        self.assertIs(self.owner.native_error.process, process)
        self.assertIs(self.owner.native_process, process)
        self.assertFalse(self.owner.step_host())

    def test_native_error_owner_still_needs_its_original_positive_close(self):
        process = SimpleNamespace(_closed=False)
        error = native_launcher.LaunchOutcomeUnknown(process, OSError("native cleanup pending"))
        native = SimpleNamespace(launch_in_job=Mock(side_effect=error),
                                 LaunchOutcomeUnknown=native_launcher.LaunchOutcomeUnknown)
        with self.assertRaises(native_launcher.LaunchOutcomeUnknown):
            self.owner.observe_launch(native, "job", "application", "command", Mock())
        self.attach_host({"settled": True, "closed": True})
        self.assertFalse(self.owner.step_host())
        process._closed = True
        self.assertTrue(self.owner.step_host())

    def test_unreadable_native_owner_does_not_replace_original_error_or_allow_exit(self):
        class UnknownOwner(RuntimeError):
            @property
            def native_launch_owner(self):
                raise KeyboardInterrupt()
        error = UnknownOwner()
        native = SimpleNamespace(launch_in_job=Mock(side_effect=error))
        with self.assertRaises(UnknownOwner) as raised:
            self.owner.observe_launch(native, "job", "application", "command", Mock())
        self.assertIs(raised.exception, error)
        self.attach_host({"settled": True, "closed": True})
        self.assertFalse(self.owner.step_host())
        self.assertTrue(self.owner.native_transfer_unknown)

    def test_bad_exception_properties_and_host_diagnostics_do_not_replace_primary(self):
        class BadDiagnostic(RuntimeError):
            @property
            def reason(self):
                raise OSError("reason unavailable")
            @property
            def detail(self):
                raise KeyboardInterrupt()
        host = self.attach_host()
        host._note_recovery_error.side_effect = OSError("logger unavailable")
        original = BadDiagnostic()
        self.owner.failure(original)
        self.assertIs(self.owner.errors["primary"], original)
        self.assertEqual(self.raw["infrastructure_failure"], "BadDiagnostic")
        self.assertIn("diagnostic_reason", self.owner.errors)
        self.assertIn("diagnostic_detail", self.owner.errors)
        self.assertIn("host_diagnostic", self.owner.errors)
        self.assertTrue(host._recovering)

    def test_no_launcher_is_cleanup_only_after_complete_construction_without_create(self):
        host = self.attach_host()
        host.launcher = None
        self.owner.create_attempted = True
        self.assertFalse(self.owner.step_host())
        self.owner.create_attempted = False
        host._construction_unknown = OSError("partial identity handle")
        self.assertFalse(self.owner.step_host())
        host._construction_unknown = None
        self.assertTrue(self.owner.step_host())

    def test_handoff_or_root_exit_does_not_prove_local_native_close(self):
        receipt = {"settled": True, "closed": False, "guardian_handoff": True}
        host = self.attach_host(receipt, closed=False)
        process = SimpleNamespace(_closed=False)
        self.owner.native_process, self.owner.create_attempted = process, True
        self.assertFalse(self.owner.step_host())
        host.launcher._closed = True
        self.assertFalse(self.owner.step_host())
        process._closed = True
        self.assertTrue(self.owner.step_host())
        self.assertIs(self.owner.native_process, process)

    def test_settlement_requires_exact_positive_receipt_and_close_boolean(self):
        host = self.attach_host({"settled": 1, "closed": True})
        self.assertFalse(self.owner.step_host())
        host.settle_release.return_value = {"settled": True, "closed": True}
        host.launcher._closed = 1
        self.assertFalse(self.owner.step_host())
        host.launcher._closed = True
        self.assertTrue(self.owner.step_host())

    def test_none_receipt_cannot_discharge_an_existing_launcher(self):
        self.attach_host(None)
        self.assertFalse(self.owner.step_host())
        self.assertFalse(self.owner.host_settled)

    def test_stop_failure_and_repeated_interrupts_still_settle_same_original_host(self):
        pending = {"settled": False, "closed": False}
        settled = {"settled": True, "closed": True}
        host = self.attach_host()
        host.settle_release.side_effect = [KeyboardInterrupt(), pending, settled]
        original = OSError("initial observation failure")
        self.owner.failure(original)
        with patch.object(Path, "touch", side_effect=OSError("stop unavailable")), \
                patch.object(fixture.time, "sleep", side_effect=[KeyboardInterrupt(), None]):
            self.owner.finish_host()
        self.assertTrue(self.owner.host_settled)
        self.assertIs(self.owner.host, host)
        self.assertIs(self.owner.errors["primary"], original)
        self.assertIn("stop_publication", self.owner.errors)
        self.assertIn("recovery", self.owner.errors)
        self.assertIn("recovery_interrupt", self.owner.errors)
        self.assertEqual(host.settle_release.call_count, 3)
        self.assertTrue(all(call.kwargs == {"max_iterations": 1} for call in host.settle_release.call_args_list))

    def test_owned_close_waits_for_host_and_unknown_close_is_never_retried(self):
        close = Mock(side_effect=OSError("close acknowledgement unknown"))
        self.owner.defer_cleanup("events", close)
        self.assertFalse(self.owner.step_cleanup())
        close.assert_not_called()
        self.owner.host_settled = True
        self.assertFalse(self.owner.step_cleanup())
        self.assertFalse(self.owner.step_cleanup())
        close.assert_called_once()
        self.assertEqual(self.owner.cleanup[0]["state"], "unknown")
        self.assertIs(self.owner.cleanup[0]["action"], close)

    def test_close_success_with_interrupted_publication_is_not_replayed(self):
        class InterruptedRecord(dict):
            def __setitem__(self, key, value):
                if key == "state" and value == "closed":
                    raise KeyboardInterrupt()
                super().__setitem__(key, value)
        close = Mock()
        self.owner.host_settled = True
        self.owner.cleanup = [InterruptedRecord(name="events", action=close, state="pending")]
        with self.assertRaises(KeyboardInterrupt):
            self.owner.step_cleanup()
        self.assertFalse(self.owner.step_cleanup())
        close.assert_called_once()


class WrapperBoundaryTests(unittest.TestCase):
    """Exercise the wrapper's pure path with host work explicitly replaced."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.spec = {"directory": str(self.directory), "token": "fixture", "source_pin": {"test": "pin"},
            "data_dir": str(self.directory), "command": "synthetic", "case": "exit_0",
            "guardian": {"epoch": "fixture", "pid": 123, "birth": "456", "endpoint_instance_id": "fixture"}}
        self.payload = base64.b64encode(json.dumps(self.spec).encode()).decode()

    def invoke(self, run, *, check=None, settle=None, write=None):
        with patch.object(fixture, "assert_source", side_effect=check) as source, \
                patch.object(fixture, "authorize", return_value=(self.directory, {})), \
                patch.object(fixture, "tick", return_value=10), \
                patch.object(wrapper_host, "_owned_interrupts", side_effect=lambda _: nullcontext()), \
                patch.object(wrapper_host.WrapperHost, "run", autospec=True, side_effect=run) as execute, \
                patch.object(wrapper_host.WrapperHost, "settle_release", autospec=True, side_effect=settle) as release, \
                patch.object(fixture, "write", wraps=fixture.write, side_effect=write):
            release.return_value = None
            result = fixture.wrapper(self.payload)
        return result, source, execute, release

    def test_owned_stderr_redirect_keeps_production_emitter_and_native_fd_operations_unchanged(self):
        original_emit = wrapper_host.emit
        def run(host):
            wrapper_host.emit({"event": "pure_test_record"})
            return 7
        with patch.object(fixture.os, "dup") as dup, patch.object(fixture.os, "dup2") as dup2, \
                patch.object(fixture.os, "close") as close:
            result, source, execute, release = self.invoke(run)
        self.assertEqual(result, 7)
        self.assertIs(wrapper_host.emit, original_emit)
        self.assertEqual(json.loads((self.directory / "wrapper-events.jsonl").read_text("utf-8")),
                         {"event": "pure_test_record"})
        raw = json.loads((self.directory / "wrapper-result.json").read_text("utf-8"))
        self.assertTrue(raw["local_cleanup_closed"])
        self.assertIsNone(raw["infrastructure_failure"])
        self.assertEqual(source.call_count, 3)
        execute.assert_called_once()
        release.assert_called_once()
        dup.assert_not_called()
        dup2.assert_not_called()
        close.assert_not_called()

    def test_source_drift_before_run_refuses_new_work_but_does_not_gate_recovery(self):
        calls = []
        def check(_):
            calls.append("source")
            if len(calls) >= 3:
                raise RuntimeError("source changed")
        result, source, execute, release = self.invoke(Mock(return_value=0), check=check)
        self.assertEqual(result, 125)
        self.assertEqual(source.call_count, 3)
        execute.assert_not_called()
        release.assert_called_once()
        raw = json.loads((self.directory / "wrapper-result.json").read_text("utf-8"))
        self.assertTrue(raw["local_cleanup_closed"])
        self.assertIsNotNone(raw["infrastructure_failure"])

    def test_stop_publication_failure_cannot_skip_release_after_run_failure(self):
        with patch.object(Path, "touch", side_effect=OSError("stop unavailable")):
            result, _, execute, release = self.invoke(Mock(side_effect=KeyboardInterrupt()))
        self.assertEqual(result, 125)
        execute.assert_called_once()
        release.assert_called_once()
        raw = json.loads((self.directory / "wrapper-result.json").read_text("utf-8"))
        self.assertTrue(raw["local_cleanup_closed"])
        self.assertEqual(raw["infrastructure_failure"], "KeyboardInterrupt")

    def test_result_artifact_failure_after_positive_cleanup_is_failed_measurement(self):
        result, _, execute, release = self.invoke(Mock(return_value=0), write=OSError("artifact unavailable"))
        self.assertEqual(result, 125)
        execute.assert_called_once()
        release.assert_called_once()
        self.assertFalse((self.directory / "wrapper-result.json").exists())


if __name__ == "__main__":
    unittest.main()
