"""Pure protocol/COM-route tests; never call Windows or dispatch a process."""
import copy
import ctypes as c
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("desktop_launch", Path(__file__).with_name("probe_adaptive_desktop_launch.py"))
launch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launch)


def identities():
    shared = dict(session_id=1, token_session_id=1, user_sid="private-user", logon_sid="private-logon",
                  authentication_luid="private-auth", elevated=False, integrity_rid=8192, in_any_job=False)
    caller = dict(shared, pid=11, creation_filetime="100", image_path=r"C:\Python\python.exe", in_any_job=True)
    desktop = dict(shared, pid=22, creation_filetime="50", image_path=r"C:\Windows\explorer.exe")
    child = dict(shared, pid=33, creation_filetime="200", image_path=r"C:\Python\pythonw.exe")
    return caller, desktop, child


class FakeChildQueries:
    def __init__(self, desktop, child):
        self.rows = {22: desktop, 33: child}
        self.closed = []
        self.binding = (101, 22)

    def open_process(self, pid):
        return pid

    def read_process(self, handle, pid):
        assert handle == pid
        return copy.deepcopy(self.rows[pid])

    def close(self, handle):
        self.closed.append(handle)

    def desktop(self):
        return self.binding


class LaunchProtocolTests(unittest.TestCase):
    def test_fixed_launch_uses_only_sibling_pythonw_and_owned_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            python, pythonw, fixture = root / "python.exe", root / "pythonw.exe", root / "child.py"
            for path in (python, pythonw, fixture):
                path.touch()
            with mock.patch.object(launch, "CHILD", fixture):
                executable, arguments = launch.fixed_launch(python, root / "nonce directory", "a" * 32)
                self.assertEqual(Path(executable), pythonw.resolve())
                self.assertTrue(arguments.startswith("-I "))
                self.assertIn("--run-directory", arguments)
                self.assertIn("--nonce " + "a" * 32, arguments)
                with self.assertRaises(launch.ProbeError):
                    launch.fixed_launch(fixture, root, "a" * 32)

    def test_cli_requires_explicit_dispatch_option(self):
        with mock.patch.object(launch, "run_probe") as run, mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                launch.main(["--output-directory", "unused"])
        run.assert_not_called()

    def test_ready_requires_matching_nonce_and_exact_new_identity(self):
        caller, desktop, child = identities()
        ready = dict(schema_version=1, nonce="a" * 32, process=launch.preflight._public_process(child))
        self.assertEqual(launch.validate_ready(ready, "a" * 32)["pid"], 33)
        for replacement in (False, 0, -1, "33"):
            bad = copy.deepcopy(ready)
            bad["process"]["pid"] = replacement
            with self.assertRaises(launch.ProbeError):
                launch.validate_ready(bad, "a" * 32)
        with self.assertRaises(launch.ProbeError):
            launch.validate_ready(ready, "b" * 32)

    def test_child_native_identity_and_desktop_rechecked_before_ack(self):
        caller, desktop, child = identities()
        api = FakeChildQueries(desktop, child)
        context = dict(caller=caller, desktop=desktop, binding=(101, 22))
        ready = dict(schema_version=1, nonce="a" * 32, process=launch.preflight._public_process(child))
        handle, observed = launch.verify_child(api, ready, "a" * 32, context, child["image_path"])
        self.assertEqual(handle, 33)
        self.assertEqual(observed, child)
        self.assertEqual(api.closed, [22])  # child remains held for exact exit verification

    def test_native_child_mismatch_never_keeps_handle_or_acknowledges(self):
        for field, replacement in (("creation_filetime", "201"), ("image_path", r"C:\Other\pythonw.exe"),
                                   ("authentication_luid", "other"), ("in_any_job", True),
                                   ("elevated", True), ("integrity_rid", 12288)):
            with self.subTest(field=field):
                caller, desktop, child = identities()
                ready = dict(schema_version=1, nonce="a" * 32, process=launch.preflight._public_process(child))
                actual = dict(child, **{field: replacement})
                api = FakeChildQueries(desktop, actual)
                with self.assertRaises(launch.ProbeError):
                    launch.verify_child(api, ready, "a" * 32, dict(caller=caller, desktop=desktop, binding=(101, 22)), child["image_path"])
                self.assertEqual(api.closed, [33])

    def test_desktop_replacement_closes_both_query_handles(self):
        caller, desktop, child = identities()
        api = FakeChildQueries(dict(desktop, creation_filetime="51"), child)
        ready = dict(schema_version=1, nonce="a" * 32, process=launch.preflight._public_process(child))
        with self.assertRaises(launch.ProbeError):
            launch.verify_child(api, ready, "a" * 32, dict(caller=caller, desktop=desktop, binding=(101, 22)), child["image_path"])
        self.assertEqual(api.closed, [22, 33])

    def test_acknowledged_file_or_com_success_alone_cannot_prove_completion(self):
        child = identities()[2]
        done = dict(schema_version=1, nonce="a" * 32, outcome="acknowledged", errors=[], process=launch.preflight._public_process(child))
        self.assertTrue(launch.completion_verified(done, "a" * 32, child, 0))
        for exit_code in (None, False, 2, 259):
            self.assertFalse(launch.completion_verified(done, "a" * 32, child, exit_code))
        self.assertFalse(launch.completion_verified(dict(done, outcome="ack_timeout"), "a" * 32, child, 0))
        self.assertFalse(launch.completion_verified(done, "b" * 32, child, 0))
        self.assertFalse(launch.completion_verified({}, "a" * 32, child, 0))
        self.assertFalse(launch.completion_verified(dict(done, errors=[{"stage": "unverified"}]), "a" * 32, child, 0))

    def test_evidence_parser_rejects_duplicate_nonfinite_and_oversize(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "evidence.json"
            for contents in ('{"nonce":"a","nonce":"b"}', '{"n":NaN}', '{"n":1e999}', '[]', ' ' * 16385):
                path.write_text(contents, encoding="utf-8")
                with self.assertRaises((launch.ProbeError, json.JSONDecodeError)):
                    launch.read_json(path)

    def test_errors_export_codes_not_private_messages(self):
        error = RuntimeError("C:/private/account or secret")
        self.assertNotIn("private", json.dumps(launch._safe_error(error)))

    def test_done_without_ready_is_diagnostic_only_and_preserves_failed_gate(self):
        child = dict(identities()[2], in_any_job=True)
        done = dict(schema_version=1, nonce="a" * 32, outcome="observation_unknown",
                    errors=[{"stage": "unsupported_self_identity"}], process=launch.preflight._public_process(child))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "done.json").write_text(json.dumps(done), encoding="utf-8")
            report = dict(candidate=False, child_verified=False, child_exit_verified=False,
                          result="launch_outcome_unknown", errors=[])
            with mock.patch.object(launch.preflight, "NativeReadOnly") as native:
                launch.add_unverified_child_diagnostic(report, directory, "a" * 32)
            native.assert_not_called()
            self.assertFalse((directory / "ready.json").exists())
            diagnostic = report["child_self_report_unverified"]
            self.assertEqual(diagnostic["verification"], "child_self_report_unverified")
            self.assertTrue(diagnostic["process"]["in_any_job"])
            self.assertEqual(diagnostic["reported_errors"], [{"stage": "unsupported_self_identity"}])
            self.assertFalse(diagnostic["identity_verified"])
            self.assertFalse(diagnostic["exit_verified"])
            self.assertFalse(report["candidate"])
            self.assertFalse(report["child_verified"])
            self.assertFalse(report["child_exit_verified"])
            self.assertEqual(report["result"], "launch_outcome_unknown")

    def test_unverified_done_claiming_ack_cannot_promote_and_private_errors_are_filtered(self):
        done = dict(schema_version=1, nonce="a" * 32, outcome="acknowledged",
                    errors=[{"stage": "C:/private/secret", "detail": "secret"}])
        summary = launch.summarize_unverified_child_report(done, "a" * 32)
        self.assertFalse(summary["identity_verified"])
        self.assertFalse(summary["exit_verified"])
        self.assertNotIn("private", json.dumps(summary))
        self.assertNotIn("secret", json.dumps(summary))
        with self.assertRaises(launch.ProbeError):
            launch.summarize_unverified_child_report(done, "b" * 32)

    def test_unverified_done_read_is_bounded_and_does_not_trigger_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "done.json").write_text(" " * 16385, encoding="utf-8")
            report = dict(candidate=False, child_verified=False, retries=0, errors=[])
            launch.add_unverified_child_diagnostic(report, directory, "a" * 32)
            self.assertNotIn("child_self_report_unverified", report)
            self.assertEqual(report["errors"], [{"stage": "evidence_too_large"}])
            self.assertFalse(report["candidate"])
            self.assertEqual(report["retries"], 0)

    def test_network_device_and_other_output_roots_rejected_before_native_query(self):
        for path in (r"\\server\share\probe", r"\\?\C:\probe", "relative"):
            with self.subTest(path=path):
                with self.assertRaises(launch.ProbeError):
                    launch.local_output_root(path)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(launch.ProbeError) as failure:
                launch.local_output_root(Path(temporary))
            self.assertEqual(str(failure.exception), "isolated_worktree_output_required")

    def test_ready_does_not_accept_boolean_numeric_aliases(self):
        child = identities()[2]
        ready = dict(schema_version=1, nonce="a" * 32, process=launch.preflight._public_process(child))
        for field in ("session_id", "integrity_rid"):
            malformed = copy.deepcopy(ready)
            malformed["process"][field] = True
            with self.assertRaises(launch.ProbeError):
                launch.validate_ready(malformed, "a" * 32)
        with self.assertRaises(launch.ProbeError):
            launch.validate_ready(dict(ready, schema_version=True), "a" * 32)

    def test_dispatch_worker_never_retries_failed_call_or_dispatches_after_deadline(self):
        for now, expected_calls in ((100.0, 1), (106.0, 0)):
            with self.subTest(now=now):
                caller, desktop, child = identities()
                api = FakeChildQueries(desktop, child)
                api.rows[11] = caller
                api.expected_explorer = lambda: desktop["image_path"]
                automation = mock.Mock()
                automation.dispatch_fixed_probe.side_effect = launch.ProbeError("synthetic_dispatch_failure")
                state, complete = {"errors": [], "stop_dispatch": threading.Event()}, threading.Event()
                with mock.patch.object(launch.preflight, "NativeReadOnly", return_value=api), \
                        mock.patch.object(launch, "DesktopAutomation", return_value=automation), \
                        mock.patch.object(launch.os, "getpid", return_value=11), \
                        mock.patch.object(launch.sys, "executable", caller["image_path"]), \
                        mock.patch.object(launch.time, "monotonic", return_value=now):
                    launch.dispatch_worker(state, complete, "fixed-pythonw", "fixed-arguments", Path("isolated"), 115.0)
                self.assertEqual(automation.dispatch_fixed_probe.call_count, expected_calls)
                self.assertFalse(state.get("com_returned_successfully", False))
                self.assertTrue(complete.is_set())
                self.assertEqual(api.closed, [22, 11])
                automation.close.assert_called_once()


class DesktopComRouteTests(unittest.TestCase):
    def modules(self, wrong_window=False):
        pythoncom = ModuleType("pythoncom")
        for name, value in dict(COINIT_APARTMENTTHREADED=2, CLSCTX_ALL=23, IID_IDispatch="IDispatch",
                                IID_IUnknown="IUnknown", IID_IServiceProvider="IServiceProvider",
                                VT_BYREF=0x4000, VT_I4=3, VT_EMPTY=0, DISPATCH_METHOD=1,
                                DISPATCH_PROPERTYGET=2).items():
            setattr(pythoncom, name, value)
        pythoncom.MakeIID = lambda value: value
        pythoncom.CoInitializeEx = mock.Mock()
        pythoncom.CoUninitialize = mock.Mock()
        windows, found, provider, browser, view, background, application, verified, dispatch = [mock.Mock() for _ in range(9)]
        pythoncom.CoCreateInstance = mock.Mock(return_value=windows)
        windows.GetIDsOfNames.side_effect = lambda name: name
        def find(*arguments):
            self.assertEqual(arguments[0], "FindWindowSW")
            self.assertEqual(arguments[6], 8)
            self.assertEqual(arguments[8], 1)
            arguments[7].value = 999 if wrong_window else 101
            return found
        windows.Invoke.side_effect = find
        found.QueryInterface.return_value = provider
        provider.QueryService.return_value = browser
        browser.QueryActiveShellView.return_value = view
        view.GetWindow.return_value = 102
        view.GetItemObject.return_value = background
        background.GetIDsOfNames.side_effect = lambda name: name
        background.Invoke.return_value = application
        application.QueryInterface.return_value = verified
        verified.QueryInterface.return_value = dispatch
        dispatch.GetIDsOfNames.side_effect = lambda name: name
        client, shell_package = ModuleType("win32com.client"), ModuleType("win32com.shell")
        client.VARIANT = lambda kind, value: SimpleNamespace(varianttype=kind, value=value)
        shell_package.shell = SimpleNamespace(SID_STopLevelBrowser="top-browser", IID_IShellBrowser="IShellBrowser")
        shell_package.shellcon = SimpleNamespace(SVGIO_BACKGROUND=0)
        modules = {"pythoncom": pythoncom, "win32com": ModuleType("win32com"),
                   "win32com.client": client, "win32com.shell": shell_package}
        def window_owner(hwnd, pointer):
            c.cast(pointer, c.POINTER(launch.w.DWORD))[0] = 22
            return 1
        api = SimpleNamespace(user=SimpleNamespace(GetWindowThreadProcessId=window_owner))
        return modules, api, pythoncom, view, background, application, verified, dispatch

    def test_dispatch_is_retrieved_from_verified_desktop_folder_view(self):
        modules, api, pythoncom, view, background, application, verified, dispatch = self.modules()
        with mock.patch.dict(sys.modules, modules):
            automation = launch.DesktopAutomation(api, 101, 22)
            view.GetItemObject.assert_called_once_with(0, "IDispatch")
            background.Invoke.assert_called_once_with("Application", 0, 2, True)
            self.assertEqual(application.QueryInterface.call_args.args[1], "IUnknown")
            verified.QueryInterface.assert_called_once_with("IDispatch")
            dispatch.Invoke.assert_not_called()  # binding itself never launches
            automation.dispatch_fixed_probe("fixed-pythonw", "fixed-arguments", "isolated-directory")
            dispatch.Invoke.assert_called_once_with("ShellExecute", 0, 1, True,
                                                   "fixed-pythonw", "fixed-arguments", "isolated-directory", "open", 0)
            automation.close()
            pythoncom.CoUninitialize.assert_called_once()

    def test_wrong_desktop_binding_does_not_dispatch(self):
        modules, api, pythoncom, view, background, application, verified, dispatch = self.modules(True)
        with mock.patch.dict(sys.modules, modules):
            with self.assertRaises(launch.ProbeError):
                launch.DesktopAutomation(api, 101, 22)
            dispatch.Invoke.assert_not_called()
            pythoncom.CoUninitialize.assert_called_once()


if __name__ == "__main__":
    unittest.main()
