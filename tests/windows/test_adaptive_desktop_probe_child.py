"""Pure handshake tests: fake native queries and clock, never start a process."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / "fixtures" / "adaptive_desktop_probe_child.py"
SPEC = importlib.util.spec_from_file_location("desktop_probe_child", SOURCE)
child = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(child)
NONCE = "b" * 32
PUBLIC_FIELDS = ("pid", "creation_filetime", "session_id", "in_any_job", "elevated", "integrity_rid")


def ticket(issued=100.0, **updates):
    value = dict(schema_version=1, nonce=NONCE, issued_monotonic=issued,
                 deadline_monotonic=issued + 15.0, expected_python_basename="pythonw.exe")
    value.update(updates)
    return value


class FakeClock:
    def __init__(self, now=100.0):
        self.now = now
        self.sleeps = []
        self.on_sleep = None

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        assert 0 < seconds <= 0.05
        self.sleeps.append(seconds)
        self.now += seconds
        if self.on_sleep:
            self.on_sleep()


class FakeQueries:
    def __init__(self):
        self.opened = []
        self.reads = []
        self.closed = []
        self.failure = None
        self.change = None
        self.close_error = None
        self.identity = dict(pid=123, creation_filetime="134342315823996135", session_id=2,
                             token_session_id=2, in_any_job=False, elevated=False, integrity_rid=0x2000,
                             image_path=r"C:\Private\Python\pythonw.exe", user_sid="private-user",
                             logon_sid="private-logon", authentication_luid="private-luid")

    def open_process(self, pid):
        self.opened.append(pid)
        return 456

    def read_process(self, handle, pid):
        self.reads.append((handle, pid))
        if self.failure:
            raise self.failure
        result = copy.deepcopy(self.identity)
        if self.change and len(self.reads) == 2:
            result[self.change] = "changed"
        return result

    def close(self, handle):
        self.closed.append(handle)
        if self.close_error:
            raise self.close_error


class ChildProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / NONCE
        self.directory.mkdir()
        self.clock = FakeClock()
        self.api = FakeQueries()
        self.native_factory = mock.Mock(side_effect=AssertionError("No native calls in pure tests"))
        self.module = SimpleNamespace(NativeReadOnly=self.native_factory,
                                      _public_process=lambda value: {key: value[key] for key in PUBLIC_FIELDS})
        self.collector = mock.Mock(side_effect=lambda api, handle, identity, **kwargs:
                                   {"self": self.module._public_process(identity)})
        self.write("request.json", ticket())

    def write(self, name, value):
        (self.directory / name).write_text(json.dumps(value), encoding="utf-8")

    def done(self):
        return json.loads((self.directory / "done.json").read_text(encoding="utf-8"))

    def run_child(self):
        with mock.patch.object(child.os, "getpid", return_value=123):
            code = child.run_probe(self.directory, NONCE, api=self.api, preflight_module=self.module,
                                   clock=self.clock, sleeper=self.clock.sleep, diagnostic_collector=self.collector)
        self.native_factory.assert_not_called()
        return code

    def acknowledge(self):
        self.write("ack.json", dict(schema_version=1, nonce=NONCE, accepted=True))

    def test_ack_success_rechecks_self_and_exports_no_private_values(self):
        self.clock.on_sleep = self.acknowledge
        self.assertEqual(self.run_child(), 0)
        self.assertEqual(self.api.opened, [123, 123])
        self.assertEqual(self.api.reads, [(456, 123)] * 4)
        self.assertEqual(self.api.closed, [456, 456])
        self.collector.assert_called_once()
        self.assertEqual(self.done()["outcome"], "acknowledged")
        for name in ("ready.json", "done.json"):
            raw = (self.directory / name).read_text(encoding="utf-8")
            for value in ("Private", "private-user", "private-logon", "private-luid", "image_path"):
                self.assertNotIn(value, raw)
            self.assertEqual(set(json.loads(raw)["process"]), set(PUBLIC_FIELDS))

    def test_expired_ticket_does_not_query_native_or_publish_ready(self):
        self.clock.now = 115.0
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.api.opened, [])
        self.assertEqual(self.done()["outcome"], "ticket_expired")
        self.assertFalse((self.directory / "ready.json").exists())

    def test_ticket_rejects_future_duration_nonfinite_bool_and_wrong_image(self):
        invalid = (dict(issued_monotonic=100.2, deadline_monotonic=115.2),
                   dict(deadline_monotonic=115.1), dict(deadline_monotonic=114.9),
                   dict(issued_monotonic=float("nan")), dict(deadline_monotonic=float("inf")),
                   dict(issued_monotonic=True), dict(schema_version=True), dict(nonce="a" * 32),
                   dict(expected_python_basename="python.exe"), dict(payload="anything"))
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(child.ProtocolError):
                child.validate_ticket(ticket(**changes), NONCE, 100.0)
        self.assertEqual(child.validate_ticket(ticket(), NONCE, 99.95), 115.0)

    def test_ack_timeout_is_bounded_to_ten_seconds_and_short_sleeps(self):
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ack_timeout")
        self.assertLessEqual(self.clock.now, 110.0)
        self.assertTrue(self.clock.sleeps)
        self.assertTrue(all(value <= 0.05 for value in self.clock.sleeps))

    def test_ticket_deadline_bounds_remaining_ack_time(self):
        self.clock.now = 111.0
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ticket_expired")
        self.assertLessEqual(self.clock.now, 115.0)

    def test_ack_arriving_at_deadline_is_not_accepted(self):
        def late_ack():
            self.acknowledge()
            self.clock.now = 115.0
        self.clock.on_sleep = late_ack
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ticket_expired")

    def test_observation_consuming_ticket_prevents_ready_and_ack(self):
        read = self.api.read_process
        def delayed_read(handle, pid):
            result = read(handle, pid)
            if len(self.api.reads) == 2:
                self.clock.now = 115.0
                self.acknowledge()
            return result
        with mock.patch.object(self.api, "read_process", side_effect=delayed_read):
            self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ticket_expired")
        self.assertFalse((self.directory / "ready.json").exists())

    def test_ready_publication_consuming_ticket_cannot_accept_ack(self):
        publish = child.publish_json
        def delayed_publish(directory, nonce, name, payload):
            publish(directory, nonce, name, payload)
            if name == "ready.json":
                self.clock.now = 115.0
                self.acknowledge()
        with mock.patch.object(child, "publish_json", side_effect=delayed_publish):
            self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ticket_expired")

    def test_ack_mismatch_and_extra_fields_are_not_accepted(self):
        for value in (dict(schema_version=1, nonce="a" * 32, accepted=True),
                      dict(schema_version=True, nonce=NONCE, accepted=True),
                      dict(schema_version=1, nonce=NONCE, accepted=1),
                      dict(schema_version=1, nonce=NONCE, accepted=False),
                      dict(schema_version=1, nonce=NONCE, accepted=True, extra="x")):
            with self.subTest(value=value):
                self.assertFalse(child.ack_matches(value, NONCE))

    def test_self_query_error_is_sanitized_and_closes_handle(self):
        self.api.failure = RuntimeError("secret SID or private-path")
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.api.closed, [456])
        self.assertEqual(self.done()["outcome"], "observation_unknown")
        self.assertNotIn("secret", json.dumps(self.done()))
        self.assertFalse((self.directory / "ready.json").exists())

    def test_known_numeric_native_error_is_kept_without_text(self):
        error = RuntimeError("private-user")
        error.win32_error = 5
        self.api.failure = error
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["errors"], [{"stage": "self_observation_failed", "win32_error": 5}])

    def test_cleanup_failure_cannot_publish_ready_or_succeed(self):
        self.api.close_error = RuntimeError("private cleanup")
        self.assertEqual(self.run_child(), 2)
        self.assertFalse((self.directory / "ready.json").exists())
        self.assertEqual(self.done()["outcome"], "observation_unknown")

    def test_self_identity_change_rejects_before_ready(self):
        self.api.change = "creation_filetime"
        self.assertEqual(self.run_child(), 2)
        self.assertFalse((self.directory / "ready.json").exists())

    def test_unknown_job_elevation_integrity_and_basename_each_disqualify_self(self):
        for key, value in (("in_any_job", None), ("elevated", True), ("integrity_rid", 0x3000),
                           ("image_path", r"C:\Private\python.exe")):
            with self.subTest(key=key):
                api = FakeQueries()
                api.identity[key] = value
                with mock.patch.object(child.os, "getpid", return_value=123):
                    public, supported = child.observe_self(self.module, api)
                self.assertFalse(supported)
                self.assertEqual(public["pid"], 123)

    def test_in_job_child_publishes_ready_and_collects_only_after_identity_ack(self):
        self.api.identity["in_any_job"] = True
        def acknowledge_after_ready():
            self.assertTrue((self.directory / "ready.json").exists())
            self.collector.assert_not_called()
            self.acknowledge()
        self.clock.on_sleep = acknowledge_after_ready
        self.assertEqual(self.run_child(), 0)
        self.assertTrue(self.done()["process"]["in_any_job"])
        self.assertTrue(self.done()["diagnostics"]["self"]["in_any_job"])
        self.assertEqual(self.done()["outcome"], "acknowledged")
        self.collector.assert_called_once()

    def test_no_ack_never_collects_job_or_lineage_diagnostics(self):
        self.assertEqual(self.run_child(), 2)
        self.collector.assert_not_called()

    def test_diagnostic_exception_after_ack_is_not_success_and_is_sanitized(self):
        self.clock.on_sleep = self.acknowledge
        self.collector.side_effect = RuntimeError("private path or SID")
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["errors"], [{"stage": "unexpected_probe_error"}])
        self.assertNotIn("private", json.dumps(self.done()))
        self.assertEqual(self.api.closed, [456, 456])

    def test_diagnostics_exceeding_ticket_are_unknown_and_do_not_succeed(self):
        self.clock.on_sleep = self.acknowledge
        def collect(*args, **kwargs):
            self.clock.now = 115.0
            return {"self": self.module._public_process(self.api.identity)}
        self.collector.side_effect = collect
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.done()["outcome"], "ticket_expired")
        self.assertNotIn("diagnostics", self.done())
        self.assertEqual(self.api.closed, [456, 456])

    def test_bounded_reader_rejects_duplicate_nonfinite_and_nonobject(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', '[]'):
            with self.subTest(raw=raw):
                (self.directory / "ack.json").write_text(raw, encoding="utf-8")
                with self.assertRaises(child.ProtocolError):
                    child.read_json(self.directory, NONCE, "ack.json")
        (self.directory / "ack.json").write_bytes(b" " * (child.MAX_JSON_BYTES + 1))
        with self.assertRaises(child.ProtocolError):
            child.read_json(self.directory, NONCE, "ack.json")

    def test_invalid_ticket_never_invokes_self_query(self):
        self.write("request.json", ticket(deadline_monotonic=999.0))
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.api.opened, [])
        self.assertEqual(self.done()["outcome"], "observation_unknown")

    def test_preexisting_ack_rejects_reuse_before_native_queries(self):
        self.acknowledge()
        self.assertEqual(self.run_child(), 2)
        self.assertEqual(self.api.opened, [])
        self.assertEqual(self.done()["outcome"], "observation_unknown")

    def test_atomic_publish_never_overwrites_existing_evidence(self):
        self.write("done.json", {"original": True})
        before = (self.directory / "done.json").read_bytes()
        self.assertEqual(self.run_child(), 2)
        self.assertEqual((self.directory / "done.json").read_bytes(), before)
        with self.assertRaises(child.ProtocolError):
            child.publish_json(self.directory, NONCE, "done.json", {"replacement": True})

    def test_production_relative_wrong_nonce_and_redirected_paths_rejected(self):
        production = Path(self.temporary.name) / ".resource-sentinel" / NONCE
        production.mkdir(parents=True)
        for directory, nonce in ((production, NONCE), (Path(NONCE), NONCE),
                                 (self.directory, "a" * 32), (self.directory, "B" * 32)):
            with self.subTest(directory=directory), self.assertRaises(child.ProtocolError):
                child.validate_run_directory(directory, nonce)
        # Pure mock covers reparse-point refusal without creating Windows links.
        real_lstat = Path.lstat
        def redirected(path, *args, **kwargs):
            value = real_lstat(path, *args, **kwargs)
            if path == self.directory:
                return SimpleNamespace(st_mode=value.st_mode, st_file_attributes=child.REPARSE_POINT)
            return value
        with mock.patch.object(Path, "lstat", redirected), self.assertRaises(child.ProtocolError):
            child.validate_run_directory(self.directory, NONCE)

    def test_ack_symlink_is_rejected_without_native_link_creation(self):
        self.acknowledge()
        real_is_symlink = Path.is_symlink
        def symlink(path):
            return path.name == "ack.json" or real_is_symlink(path)
        with mock.patch.object(Path, "is_symlink", symlink), self.assertRaises(child.ProtocolError):
            child.read_json(self.directory, NONCE, "ack.json")

    def test_network_and_device_paths_rejected_before_filesystem_queries(self):
        for path in ("\\\\server\\share\\" + NONCE, "\\\\?\\C:\\probe\\" + NONCE,
                     "//server/share/" + NONCE):
            with self.subTest(path=path), mock.patch.object(Path, "lstat") as query:
                with self.assertRaises(child.ProtocolError):
                    child.validate_run_directory(path, NONCE)
                query.assert_not_called()


if __name__ == "__main__":
    unittest.main()
