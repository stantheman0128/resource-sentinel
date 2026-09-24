"""Startup retry and interruption retain the original guardian owner.

The entrypoint uses explicit synthetic host steps. The close gate additionally
uses a production GuardianHost and VerifiedProcess over an in-process backend.
No test starts a guardian process, opens a pipe, or touches a live ledger.
"""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import guardian_host as module
from sentinel.adaptive.guardian_host import GuardianHost, GuardianHostRefused
from sentinel.adaptive.host_authority import HostCapabilityUnsupported
from tests.test_adaptive_guardian_host import EPOCH, GUARDIAN, ProcessBackend


class EndFixture(BaseException):
    """Stop observing a resident synthetic loop without claiming clean exit."""


class StartupHost:
    def __init__(self, steps, *, repeat_error=None):
        self.steps = list(steps)
        self.repeat_error = repeat_error
        self.events = []
        self.records = []
        self.guardian = object()
        self.owner = object()
        self.original_guard = object()
        self._registration = SimpleNamespace(pending=False, guard=self.original_guard)
        self._runtime_error = None
        self.retained_errors = []
        self.start_owners = []
        self.started = self.closed = self.draining = False
        self.close_error = None
        self.sleep_callback = None

    def emit(self, record):
        self.records.append(record)

    def _start_telemetry(self):
        """Synthetic diagnostics retain no native or filesystem resources."""

    @property
    def registration_pending(self):
        return self._registration.pending

    def start(self):
        self.events.append(("start",))
        self.start_owners.append((self.guardian, self.owner, self._registration, self._registration.guard))
        if self.steps:
            error, pending = self.steps.pop(0)
        else:
            error, pending = self.repeat_error, True
        self._registration.pending = pending
        if error is not None:
            raise error
        self.started = True
        return {"event": "fixture_started"}

    def _retain_rpc_cleanup(self, error):
        if all(item is not error for item in self.retained_errors):
            self.retained_errors.append(error)

    def _sleep(self, seconds):
        self.events.append(("sleep", seconds))
        if self.sleep_callback is not None:
            self.sleep_callback()

    def begin_drain(self):
        self.events.append(("begin_drain",))
        self.draining = True

    def run_once(self):
        self.events.append(("normal_iteration",))
        return {"event": "fixture_iteration"}

    def serve_until_stopped(self):
        self.events.append(("normal_serve",))
        return {"event": "fixture_stopping"}

    def drain_until_settled(self):
        self.events.append(("drain",))
        if not self.started or self.registration_pending:
            raise AssertionError("drain cannot replace unfinished startup custody")
        return {"event": "fixture_drained", "settled": True}

    def close(self):
        self.events.append(("close",))
        if self.registration_pending:
            raise AssertionError("entrypoint tried to close pending registration")
        if self.close_error is not None:
            raise self.close_error
        self.closed = True
        return {"event": "fixture_closed"}


class GuardianStartupRetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def arguments(self, *, iterations=1):
        return ["--data-dir", str(self.directory), "--journal-dir", str(self.directory / "journal"),
                "--guardian-epoch", EPOCH, "--iterations", str(iterations)]

    def invoke(self, host, *, iterations=1):
        with patch.object(module, "GuardianHost", return_value=host) as constructor:
            try:
                code = module.main(self.arguments(iterations=iterations))
            finally:
                constructor.assert_called_once()
        return code, host.records

    def assert_same_startup_owners(self, host, expected_count):
        self.assertEqual(len(host.start_owners), expected_count)
        original = host.start_owners[0]
        for attempt in host.start_owners:
            for actual, expected in zip(attempt, original):
                self.assertIs(actual, expected)
        self.assertIs(host._registration.guard, host.original_guard)

    def test_pending_refusal_or_unexpected_exception_retries_same_original_host_to_success(self):
        for error in (GuardianHostRefused("fixture_registration_pending"),
                      RuntimeError("fixture startup acknowledgement unknown")):
            with self.subTest(error=type(error).__name__):
                host = StartupHost([(error, True), (None, False)])
                code, records = self.invoke(host)
                self.assertEqual(code, module.EXIT_OK)
                self.assert_same_startup_owners(host, 2)
                self.assertIs(host._runtime_error, error)
                self.assertIn(error, host.retained_errors)
                self.assertEqual([event[0] for event in host.events],
                    ["start", "sleep", "start", "normal_iteration", "drain", "close"])
                self.assertTrue(host.closed)
                self.assertTrue(any(record.get("event") == "guardian_host_registration_retained"
                                    for record in records))
                self.assertTrue(all(0 < event[1] <= 1 for event in host.events if event[0] == "sleep"))

    def test_interrupted_pending_startup_finishes_same_attempt_then_drains_without_normal_work(self):
        for iterations in (0, 2):
            with self.subTest(iterations=iterations):
                interrupt = KeyboardInterrupt()
                host = StartupHost([(interrupt, True), (None, False)])
                code, _ = self.invoke(host, iterations=iterations)
                self.assertEqual(code, module.EXIT_OK)
                self.assert_same_startup_owners(host, 2)
                self.assertIs(host._runtime_error, interrupt)
                self.assertIn(interrupt, host.retained_errors)
                self.assertEqual([event[0] for event in host.events],
                    ["start", "sleep", "start", "begin_drain", "drain", "close"])
                self.assertTrue(host.draining)
                self.assertTrue(host.closed)

    def test_interrupt_during_pending_retry_delay_also_skips_normal_serve_after_success(self):
        host = StartupHost([(GuardianHostRefused("fixture_registration_pending"), True), (None, False)])

        def interrupted_delay():
            raise KeyboardInterrupt()

        host.sleep_callback = interrupted_delay
        code, _ = self.invoke(host, iterations=0)
        self.assertEqual(code, module.EXIT_OK)
        self.assert_same_startup_owners(host, 2)
        self.assertFalse(any(event[0].startswith("normal_") for event in host.events))
        self.assertTrue(host.draining)
        self.assertTrue(host.closed)

    def test_pending_registration_refuses_close_before_any_cleanup_or_identity_release(self):
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "journal",
                            guardian_epoch=EPOCH)
        backend = ProcessBackend()
        original = backend.process(GUARDIAN)
        host.guardian = original
        guard = object()
        host._registration = SimpleNamespace(pending=True, guard=guard)
        with patch.object(host, "_reap_rpc_cleanup", side_effect=AssertionError("cleanup ran before registration gate")) as reap:
            for _ in range(2):
                with self.assertRaises(GuardianHostRefused) as caught:
                    host.close()
                self.assertEqual(caught.exception.reason, "guardian_host_registration_unsettled")
        reap.assert_not_called()
        self.assertIs(host.guardian, original)
        self.assertIs(host._registration.guard, guard)
        self.assertFalse(backend.entries[original._handle].closed)
        self.assertEqual(host._closed_owners, set())

    def test_quarantined_pending_registration_stays_resident_without_replacement_or_close(self):
        error = GuardianHostRefused("fixture_registration_quarantined")
        error._native_close_outcome_unknown = True
        retained_native_owner = object()
        error._identity_handle_cleanup = (retained_native_owner,)
        host = StartupHost([], repeat_error=error)
        sleeps = 0

        def stop_observer():
            nonlocal sleeps
            sleeps += 1
            if sleeps == 2:
                raise EndFixture()

        host.sleep_callback = stop_observer
        with self.assertRaises(EndFixture):
            self.invoke(host)
        self.assert_same_startup_owners(host, 2)
        self.assertIs(host._runtime_error, error)
        self.assertEqual(host.retained_errors, [error])
        self.assertIs(host.retained_errors[0]._identity_handle_cleanup[0], retained_native_owner)
        self.assertTrue(host.registration_pending)
        self.assertFalse(host.closed)
        self.assertEqual([event[0] for event in host.events], ["start", "sleep", "start", "sleep"])

    def test_nonpending_startup_refusal_with_unknown_cleanup_does_not_return_to_shell(self):
        refusal = GuardianHostRefused("fixture_late_startup_refused")
        host = StartupHost([(refusal, False)])
        close_error = GuardianHostRefused("fixture_original_identity_close_unknown")
        host.close_error = close_error
        sleeps = 0

        def stop_observer():
            nonlocal sleeps
            sleeps += 1
            if sleeps == 2:
                raise EndFixture()

        host.sleep_callback = stop_observer
        with self.assertRaises(EndFixture):
            self.invoke(host)
        self.assert_same_startup_owners(host, 1)
        self.assertFalse(host.closed)
        self.assertEqual([event[0] for event in host.events], ["start", "close", "sleep", "close", "sleep"])

    def test_clean_preflight_refusal_keeps_original_exit_and_creates_no_owners_or_database(self):
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "journal",
                            guardian_epoch=EPOCH)
        records = []
        error = HostCapabilityUnsupported("host_foreign_parent_job")
        with patch.object(module, "GuardianHost", return_value=host), \
                patch.object(module, "read_host_capability", side_effect=error), \
                patch.object(host, "emit", side_effect=records.append), \
                patch.object(host, "close", side_effect=AssertionError("preflight owns no native resources")) as close, \
                patch("sentinel.adaptive.store.LifecycleStore", side_effect=AssertionError("preflight touched ledger")) as store:
            code = module.main(self.arguments())
        self.assertEqual(code, module.EXIT_REFUSED)
        self.assertEqual(records[-1]["event"], "guardian_host_refused")
        self.assertEqual(records[-1]["reason"], "host_foreign_parent_job")
        close.assert_not_called()
        store.assert_not_called()
        self.assertIsNone(host.guardian)
        self.assertIsNone(host.owner)
        self.assertFalse(host.registration_pending)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
