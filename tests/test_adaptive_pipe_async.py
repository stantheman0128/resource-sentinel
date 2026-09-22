"""Portable original-operation fixtures; no Windows capability is certified."""
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import pipe_windows as native
from tests.test_adaptive_pipe_windows import FixtureBackend, FixtureProcess, LOGON, SERVER


class AsyncPipeTests(unittest.TestCase):
    def setUp(self):
        self.api, self.resources = FixtureBackend(), {}
        self.registry = native.NativePipeRegistry()
        self.endpoint = native.NativePipeEndpoint(LOGON, str(uuid4()), SERVER)
        for override in (
                patch.object(native, "_backend", return_value=self.api),
                patch.object(native, "_PROCESS_RESOURCES", self.resources),
                patch.object(native.VerifiedProcess, "current", side_effect=lambda: FixtureProcess(SERVER)),
                patch.object(native.VerifiedProcess, "open", side_effect=FixtureProcess)):
            override.start()
            self.addCleanup(override.stop)
        # Unknown-outcome cases deliberately retain their fake owners through
        # the assertions. This isolated map is not cleared or presented as a
        # successful native cleanup; no fixture owns an OS handle.

    def deadline(self):
        return native.NativeDeadline.after_ms(100)

    def listener(self, *, pending=True):
        if pending:
            self.api.pending_kinds.add("connect")
        return native.NativePipeListener(self.endpoint, self.registry)

    def finish_accept(self, listener):
        operation = listener._owner._accept_operation
        if operation is not None:
            self.api.complete(operation, cancelled=True)
        self.assertTrue(listener.stop_accept())
        listener.close()
        self.assertEqual(self.registry.status().resources, 0)

    def test_idle_polls_keep_one_original_operation_event_without_native_wait(self):
        listener = self.listener()
        started = self.api.now
        self.assertIsNone(listener.poll_accept())
        original = listener._owner._operation
        event = original.event
        for _ in range(20):
            self.assertIsNone(listener.poll_accept())
            self.assertIs(listener._owner._operation, original)
            self.assertEqual(original.event, event)
        self.assertEqual(self.api.now, started)
        self.assertEqual(len(self.api.starts), 1)
        self.assertEqual(self.api.cancels, [])
        self.assertTrue(all(wait == 0 for _, _, wait in self.api.observations))
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 1, 0))
        self.finish_accept(listener)

    def test_healthy_idle_accept_survives_registry_reap(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        observed = len(self.api.observations)
        self.assertEqual(self.registry.reap(self.deadline()), native.PipeRegistryStatus(1, 1, 0))
        self.assertIs(listener._owner._operation, original)
        self.assertEqual(len(self.api.observations), observed)
        self.finish_accept(listener)

    def test_legacy_accept_and_run_cannot_replace_pending_async_operation(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            listener.accept(self.deadline())
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            listener._owner._run("read", self.deadline(), 1)
        self.assertIs(listener._owner._operation, original)
        self.assertEqual(len(self.api.starts), 1)
        self.finish_accept(listener)

    def test_delayed_completion_returns_one_borrower_and_reuses_after_disconnect(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        self.api.complete(original)
        connection = listener.poll_accept()
        self.assertIs(listener._owner._active, connection)
        self.assertIsNone(listener._owner._operation)
        self.assertEqual(len(self.api.starts), 1)
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            listener.poll_accept()
        connection.close()
        self.assertIsNone(listener.poll_accept())
        self.assertIsNot(listener._owner._operation, original)
        self.assertEqual(len(self.api.starts), 2)
        self.finish_accept(listener)

    def test_immediate_connect_still_retires_event_before_borrowing(self):
        listener = self.listener(pending=False)
        connection = listener.poll_accept()
        self.assertIsNotNone(connection)
        self.assertIsNone(listener._owner._operation)
        self.assertEqual(self.api.observations, [])
        self.assertEqual(len(self.api.closed), 1)  # original event only
        connection.close()
        self.finish_accept(listener)

    def test_idle_stop_is_terminal_and_does_not_create_an_operation(self):
        listener = self.listener()
        self.assertTrue(listener.stop_accept())
        for invoke in (listener.poll_accept, lambda: listener.accept(self.deadline())):
            with self.assertRaisesRegex(native.NativePipeError, "accept_stopped"):
                invoke()
        self.assertEqual(self.api.starts, [])
        listener.close()

    def test_stop_cancels_once_and_retains_until_positive_terminal_observation(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        for _ in range(8):
            self.assertFalse(listener.stop_accept())
            self.assertIs(listener._owner._operation, original)
        self.assertEqual(len(self.api.cancels), 1)
        self.assertEqual(len(self.api.starts), 1)
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 1, 0))
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            listener.close()
        self.api.complete(original, cancelled=True)
        self.assertTrue(listener.stop_accept())
        self.assertTrue(listener.stop_accept())
        self.assertEqual(len(self.api.cancels), 1)
        self.assertEqual(len(self.api.disconnects), 1)
        listener.close()

    def test_normal_connect_wins_cancel_race_without_publishing_new_borrower(self):
        listener = self.listener()
        listener.poll_accept()
        cancel = self.api.cancel
        def raced(handle, operation):
            cancel(handle, operation)
            self.api.complete(operation)
        self.api.cancel = raced
        self.assertTrue(listener.stop_accept())
        self.assertIsNone(listener._owner._active)
        self.assertEqual(len(self.api.cancels), 1)
        self.assertEqual(len(self.api.disconnects), 1)
        listener.close()

    def test_active_borrower_is_not_discarded_by_terminal_stop(self):
        listener = self.listener(pending=False)
        connection = listener.poll_accept()
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            listener.stop_accept()
        self.assertIs(listener._owner._active, connection)
        self.assertFalse(connection._closed)
        connection.close()
        self.assertTrue(listener.stop_accept())
        with self.assertRaisesRegex(native.NativePipeError, "accept_stopped"):
            listener.poll_accept()
        listener.close()

    def test_unknown_cancel_is_not_reissued_and_keeps_original_operation(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        self.api.cancel_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as caught:
            listener.stop_accept()
        self.assertIs(caught.exception._pipe_accept_owner, listener._owner)
        self.api.cancel_error = None
        self.assertFalse(listener.stop_accept())
        self.assertEqual(len(self.api.cancels), 1)
        self.assertIs(listener._owner._operation, original)
        self.assertEqual(self.registry.status().quarantined, 1)
        self.finish_accept(listener)

    def test_stop_wins_completion_publication_race(self):
        listener = self.listener()
        def race(operation):
            self.api.complete(operation)
            with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
                listener.stop_accept()
        self.api.on_observe = race
        self.assertIsNone(listener.poll_accept())
        self.assertIsNone(listener._owner._active)
        self.assertTrue(listener.stop_accept())
        self.assertEqual(len(self.api.starts), 1)
        listener.close()

    def test_unknown_event_acquisition_remains_retained_without_connect_or_reaping(self):
        listener = self.listener()
        create = self.api.create_event
        lost_events = []
        def unknown_create():
            lost_events.append(create())
            raise KeyboardInterrupt()
        self.api.create_event = unknown_create
        with self.assertRaises(KeyboardInterrupt):
            listener.poll_accept()
        original = listener._owner._operation
        self.assertIsNone(original.event)
        self.assertTrue(original.event_acquisition_entered)
        self.assertFalse(original.event_acquisition_known)
        self.assertEqual(self.api.starts, [])
        self.assertEqual(self.registry.reap(self.deadline()), native.PipeRegistryStatus(1, 1, 1))
        self.assertIs(listener._owner._operation, original)
        self.assertEqual(self.api.observations, [])
        self.assertEqual(self.api.close_attempts, [])
        with self.assertRaisesRegex(native.NativePipeError, "event_acquisition_unknown"):
            listener.stop_accept()
        self.assertEqual(len(lost_events), 1)

    def test_known_failed_event_acquisition_can_reap_without_invented_io(self):
        listener = self.listener()
        def known_failed():
            raise native._NativeEventCreateFailed("pipe_event_create_failed", 8)
        self.api.create_event = known_failed
        with self.assertRaises(native.NativePipeError):
            listener.poll_accept()
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(self.api.starts, [])
        self.assertEqual(self.api.observations, [])

    def test_connect_success_then_interrupt_retains_completion_and_event(self):
        listener = self.listener(pending=False)
        start = self.api.start
        def interrupted(handle, operation):
            start(handle, operation)
            raise KeyboardInterrupt()
        self.api.start = interrupted
        with self.assertRaises(KeyboardInterrupt):
            listener.poll_accept()
        original = listener._owner._operation
        self.assertTrue(original.completed)
        self.assertIsNotNone(original.event)
        self.assertTrue(listener.stop_accept())
        self.assertEqual(len(self.api.starts), 1)
        listener.close()

    def test_async_event_close_success_then_interrupt_never_recloses(self):
        listener = self.listener(pending=False)
        close = self.api.close
        def interrupted(handle):
            close(handle)
            raise KeyboardInterrupt()
        self.api.close = interrupted
        with self.assertRaises(KeyboardInterrupt):
            listener.poll_accept()
        original = listener._owner._operation
        event = original.event
        self.api.close = close
        for _ in range(3):
            self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
            with self.assertRaisesRegex(native.NativePipeError, "event_close_unknown"):
                listener.stop_accept()
        self.assertEqual(self.api.close_attempts.count(event), 1)
        self.assertIs(listener._owner._operation, original)

    def test_blocking_event_close_success_then_interrupt_never_recloses_in_except(self):
        connection = native.NativePipeConnection.connect(self.endpoint, self.deadline(), self.registry)
        close = self.api.close
        def interrupted(handle):
            close(handle)
            raise KeyboardInterrupt()
        self.api.close = interrupted
        with self.assertRaises(KeyboardInterrupt):
            connection.write_all(b"owned payload", self.deadline())
        original = connection._owner._operation
        event = original.event
        self.api.close = close
        self.assertEqual(self.api.close_attempts.count(event), 1)
        for _ in range(3):
            self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
        self.assertEqual(self.api.close_attempts.count(event), 1)

    def test_pipe_close_success_then_interrupt_prevents_every_later_native_use(self):
        listener = self.listener(pending=False)
        handle = listener._owner._handle
        close = self.api.close
        def interrupted(value):
            close(value)
            raise KeyboardInterrupt()
        self.api.close = interrupted
        with self.assertRaises(KeyboardInterrupt):
            listener.close()
        self.api.close = close
        before_observe, before_disconnect = len(self.api.observations), len(self.api.disconnects)
        for _ in range(3):
            self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
            with self.assertRaisesRegex(native.NativePipeError, "handle_close_unknown"):
                listener.close()
            with self.assertRaisesRegex(native.NativePipeError, "handle_close_unknown"):
                listener.stop_accept()
        self.assertEqual(self.api.close_attempts.count(handle), 1)
        self.assertEqual(len(self.api.observations), before_observe)
        self.assertEqual(len(self.api.disconnects), before_disconnect)

    def test_blocking_accept_still_works_after_successful_async_disconnect(self):
        listener = self.listener(pending=False)
        listener.poll_accept().close()
        listener.accept(self.deadline()).close()
        self.assertEqual(len(self.api.starts), 2)
        self.assertEqual(len(self.api.disconnects), 2)
        listener.close()

    def test_terminal_failed_connect_disconnects_before_reusing_listener(self):
        listener = self.listener()
        listener.poll_accept()
        original = listener._owner._operation
        self.api.complete(original)
        original.error = 232
        with self.assertRaisesRegex(native.NativePipeError, "pipe_io_failed"):
            listener.poll_accept()
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 0, 0))
        self.assertIsNone(listener.poll_accept())
        self.assertEqual(len(self.api.starts), 2)
        self.finish_accept(listener)


if __name__ == "__main__":
    unittest.main()
