"""Portable host/sink wiring tests; no native capability or timing evidence."""
from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.guardian_host import GuardianHost, GuardianHostRefused
from sentinel.adaptive.helper_host import HelperHost, HelperHostRefused
from sentinel.adaptive.supervisor_host import SupervisorHost, SupervisorHostRefused


IDENTITY = ProcessIdentity(101, 134343072000000001, "S-1-5-5-1-2")


class FixtureStopped(BaseException):
    """Stop a retained-loop fixture without claiming cleanup or process exit."""


class Sink:
    def __init__(self, factory):
        self.factory = factory
        self.started = self.stop_requested = False
        self.start_calls = self.finish_calls = 0
        self.records = []
        self.offer_error = self.finish_error = None
        self.status = {"stopped": True}

    def start(self):
        if self.factory.host.telemetry is not self:
            raise AssertionError("sink must be retained before start")
        self.start_calls += 1
        if self.factory.start_error is not None:
            raise self.factory.start_error
        self.started = True

    def offer(self, record, **kwargs):
        if self.offer_error is not None:
            raise self.offer_error
        if self.stop_requested:
            return False
        self.records.append((dict(record), kwargs))
        return True

    def request_stop(self):
        self.factory.order.append("telemetry_stop")
        self.stop_requested = True

    def finish(self, *, timeout):
        if timeout != .05:
            raise AssertionError("resident shutdown must remain bounded")
        self.finish_calls += 1
        if self.finish_error is not None:
            raise self.finish_error
        return dict(self.status)


class Factory:
    def __init__(self):
        self.host = None
        self.calls = []
        self.order = []
        self.start_error = None

    def __call__(self, **kwargs):
        self.calls.append(kwargs)
        return Sink(self)


class HostTelemetryTests(unittest.TestCase):
    def make_host(self, role):
        factory = Factory()
        common = {"data_dir": "telemetry-fixture", "telemetry_factory": factory}
        if role == "helper":
            host = HelperHost(**common)
            host.process = SimpleNamespace(identity=IDENTITY)
        elif role == "guardian":
            host = GuardianHost(**common, journal_dir="telemetry-fixture/recovery",
                                guardian_epoch="fixture-epoch")
            host.guardian = SimpleNamespace(identity=IDENTITY)
        else:
            host = SupervisorHost(**common, journal_dir="telemetry-fixture/recovery")
            host.startup = SimpleNamespace(_current=SimpleNamespace(identity=IDENTITY),
                                          _acquire_stage="held", close=lambda: None)
        factory.host = host
        return host, factory

    def test_exact_original_binding_is_retained_and_started_once(self):
        for role in ("helper", "guardian", "supervisor"):
            with self.subTest(role=role):
                host, factory = self.make_host(role)
                host._start_telemetry()
                original = host.telemetry
                host._start_telemetry()
                self.assertIs(host.telemetry, original)
                self.assertEqual((len(factory.calls), original.start_calls), (1, 1))
                arguments = factory.calls[0]
                self.assertEqual(arguments["role"], role)
                self.assertIs(arguments["identity"], IDENTITY)
                self.assertEqual(arguments["data_dir"], Path("telemetry-fixture"))
                expected_id = (host._telemetry_instance_id if role == "helper" else
                               host.instance_id if role == "guardian" else host._instance_id)
                self.assertEqual(arguments["instance_id"], expected_id)
                expected_exclusions = () if role == "helper" else (host.journal_dir,)
                self.assertEqual(arguments["excluded_paths"], expected_exclusions)

    def test_helper_operator_instance_wins_over_plain_host_nonce(self):
        host, factory = self.make_host("helper")
        host.instance_id = "00000000-0000-0000-0000-000000000123"
        host._start_telemetry()
        self.assertEqual(factory.calls[0]["instance_id"], host.instance_id)

    def test_explicit_fixture_sources_require_explicit_factory(self):
        host = HelperHost(data_dir="unused-fixture", clock=lambda: 1,
                          machine_source=lambda: None)
        host.process = SimpleNamespace(identity=IDENTITY)
        host._start_telemetry()
        self.assertIsNone(host.telemetry)
        factory = Factory()
        explicit = HelperHost(data_dir="unused-fixture", clock=lambda: 1,
                              machine_source=lambda: None, telemetry_factory=factory)
        explicit.process = SimpleNamespace(identity=IDENTITY)
        factory.host = explicit
        explicit._start_telemetry()
        self.assertTrue(explicit.telemetry.started)

    def test_supervisor_does_not_treat_unvalidated_current_as_identity_proof(self):
        host, factory = self.make_host("supervisor")
        host.startup._acquire_stage = "identity"
        host._start_telemetry()
        self.assertEqual(factory.calls, [])
        host.startup._acquire_stage = "binding"
        host._start_telemetry()
        self.assertIs(factory.calls[0]["identity"], IDENTITY)

    def test_helper_identity_refusal_never_constructs_sink(self):
        host, factory = self.make_host("helper")
        host.process = None
        with patch.object(host, "_capability", return_value=object()), \
                patch.object(host, "_profile", return_value=object()), \
                patch("sentinel.adaptive.store.LifecycleStore", return_value=object()), \
                patch("sentinel.adaptive.identity.VerifiedProcess.current", side_effect=OSError("fixture")):
            with self.assertRaisesRegex(HelperHostRefused, "helper_host_identity_unavailable"):
                host.start()
        self.assertEqual(factory.calls, [])

    def test_guardian_identity_refusal_never_constructs_sink(self):
        host, factory = self.make_host("guardian")
        host.guardian = None
        host.capability = host._startup_profile = host.store = host.journal = object()
        with patch("sentinel.adaptive.identity.VerifiedProcess.current", side_effect=OSError("fixture")):
            with self.assertRaisesRegex(GuardianHostRefused, "guardian_host_identity_unavailable"):
                host.start()
        self.assertEqual(factory.calls, [])

    def test_explicit_stream_preserves_original_serializer_and_skips_sink(self):
        for role in ("helper", "guardian", "supervisor"):
            with self.subTest(role=role):
                host, _ = self.make_host(role)
                host._start_telemetry()
                host.telemetry.offer_error = AssertionError("explicit stream reached sink")
                stream = io.StringIO()
                record = {"event": "fixture", "detail": "explicit-stream"}
                host.emit(record, stream=stream)
                self.assertEqual(json.loads(stream.getvalue()), record)
                self.assertEqual(host.telemetry.records, [])

    def test_hosts_route_to_their_original_sink_without_global_state(self):
        one, _ = self.make_host("guardian")
        two, _ = self.make_host("guardian")
        one._start_telemetry()
        two._start_telemetry()
        one.emit({"event": "first"})
        two.emit({"event": "second"})
        self.assertEqual([record["event"] for record, _ in one.telemetry.records], ["first"])
        self.assertEqual([record["event"] for record, _ in two.telemetry.records], ["second"])

    def test_failed_start_retains_original_sink_without_factory_retry(self):
        host, factory = self.make_host("helper")
        failure = OSError("fixture start")
        factory.start_error = failure
        host._start_telemetry()
        owner = host.telemetry
        host._start_telemetry()
        self.assertIs(host.telemetry, owner)
        self.assertIs(host._telemetry_start_error, failure)
        self.assertEqual((len(factory.calls), owner.start_calls), (1, 1))

    def test_resident_emit_failure_is_retained_without_stderr_fallback(self):
        host, _ = self.make_host("helper")
        host._start_telemetry()
        failure = OSError("fixture write")
        host.telemetry.offer_error = failure
        with patch("sys.stderr", new=SimpleNamespace(write=lambda *_: self.fail("stderr fallback"))):
            self.assertFalse(host.emit({"event": "fixture"}))
        self.assertIs(host._telemetry_emit_error, failure)

    def test_pending_control_cleanup_keeps_original_sink_running(self):
        for role, error_type in (("helper", HelperHostRefused),
                                 ("guardian", GuardianHostRefused),
                                 ("supervisor", SupervisorHostRefused)):
            with self.subTest(role=role):
                host, _ = self.make_host(role)
                host._start_telemetry()
                owner = host.telemetry
                if role == "helper":
                    host._registration_operation = SimpleNamespace(pending=True)
                elif role == "guardian":
                    host._registration = SimpleNamespace(pending=True)
                else:
                    host._creation_unknown = True
                with self.assertRaises(error_type):
                    host.close()
                self.assertIs(host.telemetry, owner)
                self.assertFalse(owner.stop_requested)
                self.assertEqual(owner.finish_calls, 0)

    def test_operator_helper_base_close_defers_telemetry_until_outer_cleanup(self):
        host, _ = self.make_host("helper")
        host._operator_ready = False  # presence represents the outer owner
        host._start_telemetry()
        record = host.close()
        self.assertFalse(host.telemetry.stop_requested)
        self.assertNotIn("telemetry", record)
        final = host._finish_telemetry({**record, "event": "helper_operator_host_closed"})
        self.assertTrue(final["telemetry"]["stopped"])

    def test_final_record_is_queued_once_and_cli_reemit_is_rejected(self):
        host, _ = self.make_host("helper")
        host._start_telemetry()
        record = host.close()
        self.assertTrue(record["telemetry"]["stopped"])
        self.assertFalse(host.emit(record))
        self.assertEqual(len(host.telemetry.records), 1)
        self.assertEqual(host.telemetry.records[0][0]["event"], "helper_host_closed")
        self.assertEqual(host.telemetry.records[0][1]["kind"].value, "event")

    def test_sink_shutdown_failure_does_not_unwind_completed_control_cleanup(self):
        host, _ = self.make_host("helper")
        host._start_telemetry()
        failure = OSError("fixture finish")
        host.telemetry.finish_error = failure
        record = host.close()
        self.assertEqual(record["event"], "helper_host_closed")
        self.assertFalse(host._started)
        self.assertFalse(record["telemetry"]["stopped"])
        self.assertIs(host._telemetry_stop_error, failure)

    def test_supervisor_closes_original_startup_before_bounded_telemetry_finish(self):
        host, factory = self.make_host("supervisor")
        host.startup.close = lambda: factory.order.append("startup_close")
        host._start_telemetry()
        host.telemetry.status = {"stopped": False, "pending": True}
        record = host.close()
        self.assertEqual(factory.order, ["startup_close", "telemetry_stop"])
        self.assertTrue(host._closed)
        self.assertFalse(record["telemetry"]["stopped"])
        self.assertEqual(host.close(), record)
        self.assertEqual(len(host.telemetry.records), 1)
        self.assertEqual(host.telemetry.finish_calls, 1)

    def test_helper_one_shot_startup_refusal_does_not_start_sink(self):
        from sentinel.adaptive.helper_control_host import run_operational
        from sentinel.adaptive.helper_host import EXIT_REFUSED

        host, factory = self.make_host("helper")
        closed = {"event": "helper_operator_host_closed"}
        stream = io.StringIO()
        with patch.object(host, "start", side_effect=RuntimeError("fixture refusal")), \
                patch.object(host, "close", return_value=closed) as close, \
                patch("sys.stderr", stream):
            self.assertEqual(run_operational(host), EXIT_REFUSED)
        close.assert_called_once_with()
        self.assertEqual(factory.calls, [])
        records = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual([record["event"] for record in records],
                         ["helper_host_refused", "helper_operator_host_closed"])

    def test_helper_failed_startup_cleanup_binds_before_pending_diagnostics(self):
        from sentinel.adaptive.helper_control_host import run_operational

        host, factory = self.make_host("helper")
        stream = io.StringIO()
        with patch.object(host, "start", side_effect=RuntimeError("fixture refusal")), \
                patch.object(host, "close", side_effect=HelperHostRefused("fixture_cleanup")), \
                patch.object(host, "_sleep", side_effect=FixtureStopped()), \
                patch("sys.stderr", stream):
            with self.assertRaises(FixtureStopped):
                run_operational(host)
        self.assertEqual(len(factory.calls), 1)
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual([record["event"] for record, _ in host.telemetry.records],
                         ["helper_host_refused", "helper_host_pending"])
        self.assertFalse(host.telemetry.stop_requested)

    def test_helper_retained_loop_reuses_original_sink(self):
        from sentinel.adaptive.helper_control_host import retain_cleanup

        host, factory = self.make_host("helper")
        with patch.object(host, "_sleep", side_effect=FixtureStopped()):
            for _ in range(2):
                with self.assertRaises(FixtureStopped):
                    retain_cleanup(host)
        self.assertEqual((len(factory.calls), host.telemetry.start_calls), (1, 1))

    def test_helper_retained_loop_cannot_invent_missing_self_identity(self):
        from sentinel.adaptive.helper_control_host import retain_cleanup

        host, factory = self.make_host("helper")
        host.process = None
        with patch.object(host, "_sleep", side_effect=FixtureStopped()), patch("sys.stderr", io.StringIO()):
            with self.assertRaises(FixtureStopped):
                retain_cleanup(host)
        self.assertEqual(factory.calls, [])
        self.assertIsNone(host.telemetry)

    def test_guardian_one_shot_cleanup_does_not_start_sink(self):
        from sentinel.adaptive.guardian_host import _close_until_settled

        host, factory = self.make_host("guardian")
        stream = io.StringIO()
        with patch.object(host, "close", return_value={"event": "guardian_host_closed"}), \
                patch("sys.stderr", stream):
            _close_until_settled(host, initial_record={"event": "guardian_host_refused"})
        self.assertEqual(factory.calls, [])
        self.assertEqual([json.loads(line)["event"] for line in stream.getvalue().splitlines()],
                         ["guardian_host_refused", "guardian_host_closed"])

    def test_guardian_retained_cleanup_binds_once_before_all_diagnostics(self):
        from sentinel.adaptive.guardian_host import _close_until_settled

        host, factory = self.make_host("guardian")
        stream = io.StringIO()
        failures = [GuardianHostRefused("fixture_cleanup"),
                    GuardianHostRefused("fixture_cleanup"), {"event": "guardian_host_closed"}]
        with patch.object(host, "close", side_effect=failures), \
                patch.object(host, "_sleep", return_value=None), patch("sys.stderr", stream):
            _close_until_settled(host, initial_record={"event": "guardian_host_refused"})
        self.assertEqual((len(factory.calls), host.telemetry.start_calls), (1, 1))
        self.assertEqual(stream.getvalue(), "")
        self.assertEqual([record["event"] for record, _ in host.telemetry.records],
                         ["guardian_host_refused", "guardian_host_cleanup_retained",
                          "guardian_host_cleanup_retained", "guardian_host_closed"])

    def test_guardian_retained_cleanup_cannot_invent_missing_self_identity(self):
        from sentinel.adaptive.guardian_host import _close_until_settled

        host, factory = self.make_host("guardian")
        host.guardian = None
        with patch.object(host, "close", side_effect=GuardianHostRefused("fixture_cleanup")), \
                patch.object(host, "_sleep", side_effect=FixtureStopped()), \
                patch("sys.stderr", io.StringIO()):
            with self.assertRaises(FixtureStopped):
                _close_until_settled(host)
        self.assertEqual(factory.calls, [])
        self.assertIsNone(host.telemetry)


if __name__ == "__main__":
    unittest.main()
