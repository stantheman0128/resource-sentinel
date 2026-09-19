"""Pure preflight tests. No Win32 call, process dispatch, Job or Task creation."""
import copy
import ctypes as c
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("desktop_preflight", Path(__file__).with_name("probe_adaptive_desktop.py"))
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def observe(api):
    with mock.patch.object(probe.os, "getpid", return_value=11):
        return probe.observe(api)


class FakeQueries:
    def __init__(self):
        identity = dict(creation_filetime="134342315823996135", image_path=r"C:\Windows\explorer.exe",
                        session_id=2, token_session_id=2, in_any_job=False, user_sid="private-user",
                        logon_sid="private-logon", authentication_luid="private-luid", elevated=False,
                        integrity_rid=0x2000)
        self.rows = {11: dict(identity, pid=11, image_path=r"C:\Private\python.exe", in_any_job=True),
                     22: dict(identity, pid=22)}
        self.reads = {}
        self.closed = []
        self.windows = [(101, 22), (101, 22)]
        self.change = None
        self.open_error = self.close_error = None

    def desktop(self):
        return self.windows.pop(0)

    def expected_explorer(self):
        return r"C:\Windows\explorer.exe"

    def open_process(self, pid):
        if pid == self.open_error:
            raise probe.ObservationError("OpenProcess(query_sync)", 5)
        return pid

    def read_process(self, handle, expected_pid):
        assert handle == expected_pid
        self.reads[handle] = self.reads.get(handle, 0) + 1
        value = copy.deepcopy(self.rows[handle])
        if self.change and handle == 22 and self.reads[handle] == 2:
            value[self.change] = "changed"
        return value

    def close(self, handle):
        self.closed.append(handle)
        if handle == self.close_error:
            raise probe.ObservationError("CloseHandle", 6)


class DesktopPreflightTests(unittest.TestCase):
    def test_foreign_caller_does_not_claim_caller_supported_or_disqualify_independent_desktop(self):
        api = FakeQueries()
        result = observe(api)
        self.assertTrue(result["candidate"])
        self.assertFalse(result["caller_host_supported"])
        self.assertEqual(result["capability_status"], "not_launch_or_control_verified")
        self.assertEqual((result["dispatches"], result["process_control_writes"]), (0, 0))
        self.assertEqual(api.closed, [22, 11])
        self.assertEqual(api.reads, {11: 2, 22: 2})

    def test_no_private_identifiers_or_paths_are_exported(self):
        serialized = json.dumps(observe(FakeQueries()))
        for private in ("private-user", "private-logon", "private-luid", "C:\\\\Private", "explorer.exe"):
            self.assertNotIn(private, serialized)

    def test_foreign_desktop_is_rejected(self):
        api = FakeQueries()
        api.rows[22]["in_any_job"] = True
        self.assertEqual(observe(api)["result"], "unsupported_desktop_foreign_job")

    def test_user_logon_luid_and_session_mismatch_each_rejected(self):
        for field in ("user_sid", "logon_sid", "authentication_luid", "session_id"):
            with self.subTest(field=field):
                api = FakeQueries()
                api.rows[22][field] = "other"
                result = observe(api)
                self.assertFalse(result["candidate"])
                self.assertEqual(result["result"], "unsupported_user_logon_or_session")

    def test_elevation_and_integrity_rejected_for_both_processes(self):
        for pid in (11, 22):
            for field, value in (("elevated", True), ("integrity_rid", 0x3000), ("integrity_rid", 0x1000)):
                with self.subTest(pid=pid, field=field, value=value):
                    api = FakeQueries()
                    api.rows[pid][field] = value
                    self.assertFalse(observe(api)["candidate"])

    def test_image_must_be_system_explorer_not_only_basename(self):
        api = FakeQueries()
        api.rows[22]["image_path"] = r"C:\Private\explorer.exe"
        self.assertEqual(observe(api)["result"], "unsupported_desktop_image")

    def test_full_held_identity_is_rechecked(self):
        for field in ("creation_filetime", "image_path", "authentication_luid", "in_any_job", "elevated"):
            with self.subTest(field=field):
                api = FakeQueries()
                api.change = field
                result = observe(api)
                self.assertEqual(result["validity"], "unknown")
                self.assertFalse(result["candidate"])
                self.assertEqual(api.closed, [22, 11])

    def test_hwnd_or_owner_change_rejected(self):
        for last in ((102, 22), (101, 23)):
            api = FakeQueries()
            api.windows[-1] = last
            result = observe(api)
            self.assertEqual(result["errors"][0]["stage"], "desktop_window_owner_changed")
            self.assertFalse(result["candidate"])

    def test_query_failure_closes_already_held_handle(self):
        api = FakeQueries()
        api.open_error = 22
        result = observe(api)
        self.assertEqual(api.closed, [11])
        self.assertEqual(result["errors"][0]["win32_error"], 5)
        self.assertFalse(result["candidate"])

    def test_close_failure_does_not_skip_other_close_or_claim_success(self):
        api = FakeQueries()
        api.close_error = 22
        result = observe(api)
        self.assertEqual(api.closed, [22, 11])
        self.assertEqual(result["validity"], "unknown")
        self.assertFalse(result["candidate"])

    def test_unexpected_error_text_not_published(self):
        api = FakeQueries()
        api.desktop = lambda: (_ for _ in ()).throw(RuntimeError("private-path-or-secret"))
        result = observe(api)
        self.assertNotIn("private-path-or-secret", json.dumps(result))
        self.assertFalse(result["candidate"])

    def test_sid_decoder_bounds_and_integrity_sid(self):
        value = c.create_string_buffer(bytes.fromhex("010100000000001000200000"))
        self.assertEqual(probe._sid_from_buffer(value, c.addressof(value)), "S-1-16-8192")
        for pointer in (0, c.addressof(value) - 1, c.addressof(value) + 8):
            with self.subTest(pointer=pointer):
                with self.assertRaises(probe.ObservationError):
                    probe._sid_from_buffer(value, pointer)

    def test_fixed_token_classes_never_use_null_size_probe(self):
        # Native TokenElevation's NULL/0 sizing attempt returned Win32 24. A
        # fixed DWORD query must succeed without making that unsupported call.
        for information_class in (12, 20):
            with self.subTest(information_class=information_class):
                calls = []

                def query(handle, requested_class, buffer, size, needed):
                    calls.append((handle, requested_class, size))
                    self.assertIsNotNone(buffer, "NULL sizing query reproduces ERROR_BAD_LENGTH")
                    self.assertEqual(size, 4)
                    c.memmove(buffer, b"\x01\x00\x00\x00", 4)
                    c.cast(needed, c.POINTER(probe.w.DWORD))[0] = 4
                    return 1

                api = probe.NativeReadOnly.__new__(probe.NativeReadOnly)
                api.advapi = SimpleNamespace(GetTokenInformation=query)
                value = api._token(123, information_class, 4)
                self.assertEqual(value.raw, b"\x01\x00\x00\x00")
                self.assertEqual(calls, [(123, information_class, 4)])

    def test_fixed_token_failed_query_is_unknown_not_zero_or_retried(self):
        api = probe.NativeReadOnly.__new__(probe.NativeReadOnly)
        query = mock.Mock(return_value=0)
        api.advapi = SimpleNamespace(GetTokenInformation=query)
        # No native API is invoked even on Windows; preserve real OS error 24.
        with mock.patch.object(probe.c, "get_last_error", return_value=24, create=True):
            with self.assertRaises(probe.ObservationError) as failure:
                api._token(123, 20, 4)
        self.assertEqual(failure.exception.stage, "GetTokenInformation_20")
        self.assertEqual(failure.exception.win32_error, 24)
        self.assertEqual(query.call_count, 1)

    def test_fixed_token_short_or_oversize_result_is_rejected(self):
        for reported in (0, 3, 5, 65537):
            with self.subTest(reported=reported):
                def query(handle, requested_class, buffer, size, needed):
                    c.cast(needed, c.POINTER(probe.w.DWORD))[0] = reported
                    return 1

                api = probe.NativeReadOnly.__new__(probe.NativeReadOnly)
                api.advapi = SimpleNamespace(GetTokenInformation=query)
                with self.assertRaises(probe.ObservationError) as failure:
                    api._token(123, 20, 4)
                self.assertEqual(failure.exception.stage, "fixed_token_result_size_invalid")

    def test_variable_token_changed_result_size_does_not_expose_unreturned_bytes(self):
        for returned in (16, 80):
            with self.subTest(returned=returned):
                calls = []

                def query(handle, information_class, buffer, size, needed):
                    calls.append(size)
                    c.cast(needed, c.POINTER(probe.w.DWORD))[0] = 64 if buffer is None else returned
                    return 0 if buffer is None else 1

                api = probe.NativeReadOnly.__new__(probe.NativeReadOnly)
                api.advapi = SimpleNamespace(GetTokenInformation=query)
                with mock.patch.object(probe.c, "get_last_error", return_value=122, create=True):
                    with self.assertRaises(probe.ObservationError) as failure:
                        api._token(123, 1, 16)
                self.assertEqual(failure.exception.stage, "token_result_size_changed")
                self.assertEqual(calls, [0, 64])

    def test_output_requires_new_absolute_nonproduction_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(probe.validate_output(root / "new.json"), root.resolve() / "new.json")
            existing = root / "old.json"
            existing.write_text("do not overwrite", encoding="utf-8")
            for path in (Path("relative.json"), existing, root / ".resource-sentinel" / "new.json", root / "missing" / "new.json"):
                with self.subTest(path=path):
                    with self.assertRaises(ValueError):
                        probe.validate_output(path)
            self.assertEqual(existing.read_text(encoding="utf-8"), "do not overwrite")


if __name__ == "__main__":
    unittest.main()
