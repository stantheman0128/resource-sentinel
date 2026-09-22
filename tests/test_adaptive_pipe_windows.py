"""Portable L1 ownership faults through a fake pipe backend; no native calls."""
import ctypes
import gc
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4
import weakref

from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive import pipe_windows as native


LOGON = "S-1-5-5-100-200"
SERVER = ProcessIdentity(os.getpid(), 134343072000000001, LOGON)
CLIENT = ProcessIdentity(os.getpid() + 100, 134343072000000002, LOGON)


class FixtureProcess:
    def __init__(self, identity):
        self.identity, self.closes, self.close_error = identity, 0, None

    def observe(self):
        return IdentityObservation(self.identity, IdentityStatus.ALIVE)

    def close(self):
        if self.close_error is not None:
            raise self.close_error
        self.closes += 1


class FixtureBackend:
    """Explicit completion model: cancellation alone never completes an op."""
    def __init__(self):
        self.now, self.next_handle = 100, 1000
        self.handles, self.closed, self.close_attempts = {}, [], []
        self.starts, self.observations, self.cancels, self.disconnects = [], [], [], []
        self.pending_kinds, self.close_failures = set(), set()
        self.terminal, self.observe_error, self.cancel_error = False, None, None
        self.on_observe, self.verify_error, self.create_error = None, None, None
        self.start_advance, self.transfer_limit = 0, None
        self.read_data = bytearray()
        self.peer_override = None

    def tick_ms(self):
        return self.now

    def handle(self, kind):
        self.next_handle += 1
        self.handles[self.next_handle] = kind
        return self.next_handle

    def create_listener(self, endpoint, owner):
        handle = self.handle("listener")
        owner._handle = handle
        if self.create_error is not None:
            raise self.create_error
        self.verify_security(handle, endpoint)
        return handle

    def open_client(self, endpoint, deadline):
        deadline.require()
        return self.handle("client")

    def verify_security(self, handle, endpoint):
        if self.verify_error is not None:
            raise self.verify_error

    def create_event(self):
        return self.handle("event")

    def close(self, handle):
        self.close_attempts.append(handle)
        if handle in self.close_failures:
            # Explicit fixture for a native BOOL-false result before closing.
            raise native._NativeCloseFailed("pipe_handle_close_failed", 6)
        if handle in self.closed:
            raise AssertionError("fixture double close")
        self.closed.append(handle)

    def peer_pid(self, handle, server_end):
        return self.peer_override or (CLIENT.pid if server_end else SERVER.pid)

    def disconnect(self, handle):
        self.disconnects.append(handle)

    def complete(self, operation, *, cancelled=False):
        operation.completed = True
        if cancelled:
            operation.error = 995
            return
        size = operation.size
        if self.transfer_limit is not None:
            size = min(size, self.transfer_limit)
        if operation.kind == "read":
            payload = bytes(self.read_data[:size]) if self.read_data else b"x" * size
            del self.read_data[:len(payload)]
            ctypes.memmove(operation.buffer, payload, len(payload))
            size = len(payload)
        operation.transferred.value = size

    def start(self, handle, operation):
        self.starts.append((handle, weakref.ref(operation)))
        operation.started = True
        self.now += self.start_advance
        if operation.kind not in self.pending_kinds:
            self.complete(operation)

    def observe(self, handle, operation, timeout_ms=0):
        self.observations.append((handle, weakref.ref(operation), timeout_ms))
        self.now += timeout_ms
        if self.on_observe is not None:
            callback, self.on_observe = self.on_observe, None
            callback(operation)
        if self.observe_error is not None:
            raise self.observe_error
        if operation.completed:
            return True
        if self.terminal:
            self.complete(operation, cancelled=True)
        return operation.completed

    def cancel(self, handle, operation):
        self.cancels.append((handle, weakref.ref(operation)))
        if self.cancel_error is not None:
            raise self.cancel_error


class PortablePipeOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.api, self.resources, self.processes = FixtureBackend(), {}, []
        self.registry = native.NativePipeRegistry()
        self.endpoint = native.NativePipeEndpoint(LOGON, str(uuid4()), SERVER)
        for override in (
                patch.object(native, "_backend", return_value=self.api),
                patch.object(native, "_PROCESS_RESOURCES", self.resources),
                patch.object(native.VerifiedProcess, "current", side_effect=lambda: self.process(SERVER)),
                patch.object(native.VerifiedProcess, "open", side_effect=self.process)):
            override.start()
            self.addCleanup(override.stop)
        self.addCleanup(self.finish_fixture_resources)

    def process(self, identity):
        process = FixtureProcess(identity)
        self.processes.append(process)
        return process

    def deadline(self, duration=100):
        return native.NativeDeadline.after_ms(duration)

    def client(self, registry=None):
        return native.NativePipeConnection.connect(self.endpoint, self.deadline(),
            self.registry if registry is None else registry)

    def listener(self, registry=None):
        return native.NativePipeListener(self.endpoint, self.registry if registry is None else registry)

    def finish_fixture_resources(self):
        # Teardown only: all objects below are fake, and terminal outcomes are
        # explicitly supplied before disposing storage. Never clear a registry
        # to turn unknown completion into an assertion of successful cleanup.
        self.api.observe_error = self.api.cancel_error = None
        self.api.close_failures.clear()
        self.api.terminal = True
        for process in self.processes:
            process.close_error = None
        for owner in list(self.resources.values()):
            with owner._lock:
                if owner._operation is not None:
                    self.api.observe(owner._handle, owner._operation, 0)
                    owner._retire_operation()
                owner._dispose()

    def pending_write(self):
        connection = self.client()
        self.api.pending_kinds.add("write")
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_timeout$") as error:
            connection.write_all(b"retained-original-buffer", self.deadline(60))
        self.assertTrue(error.exception.io_pending)
        return connection

    def test_cancel_request_retains_original_operation_buffer_and_owner_until_terminal_reap(self):
        connection = self.pending_write()
        owner = connection._owner
        operation = owner._operation
        operation_ref, owner_ref = weakref.ref(operation), weakref.ref(owner)
        buffer_address = ctypes.addressof(operation.buffer)
        overlap_address, event = ctypes.addressof(operation.overlapped), operation.event
        self.assertEqual(bytes(operation.buffer.raw[:operation.size]), b"retained-original-buffer")
        self.assertIs(self.api.cancels[0][1](), operation)
        self.assertTrue(all(item[1]() is operation for item in self.api.observations))
        self.assertNotIn(event, self.api.closed)
        with self.assertRaises(native.NativePipeError):
            connection.write_all(b"second", self.deadline())
        with self.assertRaisesRegex(native.NativePipeError, "pipe_busy"):
            connection.close()
        self.assertEqual(len(self.api.starts), 1)
        del operation, owner, connection
        gc.collect()
        self.assertIsNotNone(owner_ref())
        self.assertIsNotNone(operation_ref())
        self.assertEqual(self.registry.reap(self.deadline()).pending, 1)
        self.assertEqual(ctypes.addressof(operation_ref().buffer), buffer_address)
        self.assertEqual(ctypes.addressof(operation_ref().overlapped), overlap_address)
        self.assertEqual(operation_ref().event, event)
        self.api.terminal = True
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(self.resources, {})
        self.assertEqual(self.api.closed.count(event), 1)
        self.assertEqual(len(self.api.starts), 1)
        self.assertTrue(all(timeout <= 25 for _, _, timeout in self.api.observations))

    def test_cancel_failure_does_not_free_or_replace_unverified_operation(self):
        self.api.cancel_error = native.NativePipeError("pipe_cancel_failed", 5, io_pending=True)
        connection = self.pending_write()
        operation = connection._owner._operation
        self.assertIs(self.api.cancels[0][1](), operation)
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 1, 1))
        self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
        self.assertIs(connection._owner._operation, operation)

    def test_unclassified_completion_error_keeps_original_io_until_later_positive_observation(self):
        connection = self.client()
        self.api.pending_kinds.add("read")
        self.api.observe_error = native.NativePipeError("pipe_completion_unavailable", 123, io_pending=True)
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_completion_unavailable$"):
            connection.read_exact(8, self.deadline())
        operation = connection._owner._operation
        self.assertEqual(self.registry.reap(self.deadline()).pending, 1)
        self.assertIs(connection._owner._operation, operation)
        self.assertEqual(len(self.api.starts), 1)
        self.api.observe_error, self.api.terminal = None, True
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(len(self.api.starts), 1)

    def test_positive_completion_after_cancel_retires_only_after_observation_preserving_timeout(self):
        connection = self.client()
        self.api.pending_kinds.add("read")
        original_cancel = self.api.cancel
        observed_during_cancel = []

        def cancel(handle, operation):
            original_cancel(handle, operation)
            observed_during_cancel.append(operation.completed)
            self.api.terminal = True

        self.api.cancel = cancel
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_timeout$") as error:
            connection.read_exact(8, self.deadline(10))
        self.assertEqual(observed_during_cancel, [False])
        self.assertFalse(error.exception.io_pending)
        self.assertIsNone(connection._owner._operation)
        self.assertEqual(self.registry.status().resources, 1)
        connection.close()
        self.assertEqual(self.registry.status().resources, 0)

    def test_completed_operation_event_close_failure_stays_counted_until_successful_reap(self):
        connection = self.client()
        create_event = self.api.create_event

        def event_with_close_failure():
            event = create_event()
            self.api.close_failures.add(event)
            return event

        self.api.create_event = event_with_close_failure
        with self.assertRaisesRegex(native.NativePipeError, "pipe_handle_close_failed"):
            connection.write_all(b"completed", self.deadline())
        operation = connection._owner._operation
        self.assertTrue(operation.completed)
        event = operation.event
        self.assertEqual(self.registry.reap(self.deadline()), native.PipeRegistryStatus(1, 1, 1))
        self.assertIs(connection._owner._operation, operation)
        self.assertNotIn(event, self.api.closed)
        self.api.close_failures.remove(event)
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(self.api.closed.count(event), 1)

    def test_pipe_close_failure_retains_global_and_local_slot_for_explicit_retry(self):
        connection = self.client()
        handle = connection._owner._handle
        self.api.close_failures.add(handle)
        with self.assertRaisesRegex(native.NativePipeError, "pipe_handle_close_failed"):
            connection.close()
        self.assertEqual(self.registry.status().resources, 1)
        self.assertEqual(len(self.resources), 1)
        self.assertEqual(connection._owner._handle, handle)
        self.api.close_failures.remove(handle)
        connection.close()
        self.assertEqual(self.registry.status().resources, 0)
        self.assertEqual(self.api.closed.count(handle), 1)

    def test_identity_close_failure_keeps_original_identity_and_slot_until_retry(self):
        connection = self.client()
        handle = connection._owner._handle
        retained = connection._owner._server_process
        retained.close_error = IdentityUnavailable("private-close-detail", 5)
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_identity_close_failed$") as error:
            connection.close()
        self.assertNotIn("private-close-detail", str(error.exception))
        self.assertIs(connection._owner._server_process, retained)
        self.assertEqual(self.registry.status().resources, 1)
        self.assertEqual(retained.closes, 0)
        self.assertEqual(self.registry.status().quarantined, 1)
        retained.close_error = None
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(retained.closes, 1)
        self.assertEqual(self.api.closed.count(handle), 1)
        self.assertEqual(self.registry.status().resources, 0)

    def test_listener_close_failure_is_quarantined_and_reaped_without_slot_loss(self):
        listener = self.listener()
        handle = listener._owner._handle
        self.api.close_failures.add(handle)
        with self.assertRaisesRegex(native.NativePipeError, "pipe_handle_close_failed"):
            listener.close()
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 0, 1))
        self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
        self.api.close_failures.clear()
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(self.api.closed.count(handle), 1)

    def test_failed_borrower_disconnect_retains_original_error_and_can_be_reaped(self):
        listener = self.listener()
        connection = listener.accept(self.deadline())
        failure = native.NativePipeError("pipe_disconnect_failed", 5)
        disconnect = self.api.disconnect
        self.api.disconnect = lambda handle: (_ for _ in ()).throw(failure)
        with self.assertRaises(native.NativePipeError) as error:
            connection.close()
        self.assertIs(error.exception, failure)
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 0, 1))
        self.assertIs(listener._owner._active, connection)
        self.api.disconnect = disconnect
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertTrue(connection._closed)

    def test_created_handle_and_failed_security_cleanup_remain_reapable(self):
        original_create = self.api.create_listener

        def fail_after_creation(endpoint, owner):
            handle = original_create(endpoint, owner)
            self.api.close_failures.add(handle)
            raise native.NativePipeError("pipe_security_mismatch")

        self.api.create_listener = fail_after_creation
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_security_mismatch$"):
            self.listener()
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 0, 1))
        self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
        self.api.close_failures.clear()
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)

    def test_only_one_io_can_own_a_connection_at_a_time(self):
        connection = self.client()
        self.api.pending_kinds.add("read")
        rejected = []

        def while_pending(operation):
            with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                connection.write_all(b"concurrent", self.deadline())
            rejected.append(operation)

        self.api.on_observe = while_pending
        with self.assertRaisesRegex(native.NativePipeError, "pipe_timeout"):
            connection.read_exact(5, self.deadline(30))
        self.assertEqual(len(rejected), 1)
        self.assertEqual(len(self.api.starts), 1)
        self.assertIs(connection._owner._operation, rejected[0])

    def test_concurrent_thread_cannot_issue_second_io_or_close_active_operation(self):
        connection = self.client()
        self.api.pending_kinds.add("write")
        entered, release = threading.Event(), threading.Event()
        errors = []

        def blocked_observation(operation):
            entered.set()
            if not release.wait(timeout=5):
                raise AssertionError("fixture worker release timed out")
            self.api.complete(operation)

        def write():
            try:
                connection.write_all(b"original", self.deadline())
            except BaseException as error:
                errors.append(error)

        self.api.on_observe = blocked_observation
        worker = threading.Thread(target=write, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(timeout=2))
            for attempt in (lambda: connection.read_exact(1, self.deadline()), connection.close):
                with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                    attempt()
            self.assertEqual(len(self.api.starts), 1)
            self.assertEqual(len([kind for kind in self.api.handles.values() if kind == "event"]), 1)
        finally:
            release.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])

    def test_listener_serializes_borrowers_and_reuses_only_after_disconnect(self):
        listener = self.listener()
        first = listener.accept(self.deadline())
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
            listener.accept(self.deadline())
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
            listener.close()
        self.assertEqual(len(self.api.starts), 1)
        first.close()
        self.assertEqual(len(self.api.disconnects), 1)
        self.assertEqual(self.registry.status().resources, 1)
        second = listener.accept(self.deadline())
        self.assertIsNot(first, second)
        second.close()
        listener.close()
        self.assertEqual(len(self.api.starts), 2)
        self.assertEqual(self.registry.status().resources, 0)

    def test_partial_transfers_share_deadline_and_use_each_original_operation_once(self):
        connection = self.client()
        self.api.transfer_limit = 2
        self.api.read_data[:] = b"abcdef"
        deadline = self.deadline()
        self.assertEqual(connection.read_exact(6, deadline), b"abcdef")
        connection.write_all(b"123456", deadline)
        self.assertEqual(len(self.api.starts), 6)
        self.assertEqual(len([handle for handle in self.api.closed if self.api.handles[handle] == "event"]), 6)
        self.assertIsNone(connection._owner._operation)

    def test_completion_after_deadline_is_rejected_without_replacing_deadline(self):
        connection = self.client()
        self.api.start_advance = 101
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_timeout$"):
            connection.write_all(b"late", self.deadline(100))
        self.assertIsNone(connection._owner._operation)
        self.assertEqual(len(self.api.starts), 1)
        self.assertEqual(self.api.cancels, [])

    def test_expired_deadline_issues_no_event_or_operation(self):
        connection = self.client()
        deadline = self.deadline(10)
        self.api.now += 10
        before = dict(self.api.handles)
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_timeout$"):
            connection.write_all(b"expired", deadline)
        self.assertEqual(self.api.handles, before)
        self.assertEqual(self.api.starts, [])
        self.assertIsNone(connection._owner._operation)

    def test_pending_waits_use_finite_slices_and_cleanup_does_not_extend_timeout(self):
        self.pending_write()
        self.assertEqual([timeout for _, _, timeout in self.api.observations], [25, 25, 10, 0])
        self.assertEqual(self.api.now, 160)

    def test_registry_cap_is_process_global_across_distinct_custom_registries(self):
        registries = [native.NativePipeRegistry(), native.NativePipeRegistry()]
        listeners = [self.listener(registries[index % 2]) for index in range(128)]
        self.assertEqual([registry.status().resources for registry in registries], [64, 64])
        before = len(self.api.handles)
        for registry in (registries[0], registries[1], native.NativePipeRegistry()):
            with self.subTest(registry=id(registry)), self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                self.listener(registry)
        self.assertEqual(len(self.api.handles), before)
        self.assertEqual(len(self.processes), 128)
        self.assertEqual(len(self.resources), 128)
        listeners.pop().close()
        replacement = self.listener(native.NativePipeRegistry())
        self.assertEqual(len(self.resources), 128)
        replacement.close()
        for listener in listeners:
            listener.close()
        self.assertEqual(self.resources, {})

    def test_custom_registry_limit_and_idle_listener_slots_are_not_evicted_by_reap(self):
        registry = native.NativePipeRegistry(max_resources=1)
        listener = self.listener(registry)
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
            self.client(registry)
        self.assertEqual(registry.reap(self.deadline()), native.PipeRegistryStatus(1, 0, 0))
        listener.close()
        connection = self.client(registry)
        connection.close()
        self.assertEqual(registry.status().resources, 0)

    def test_reap_maximum_limits_original_operations_per_pass(self):
        connections = [self.pending_write() for _ in range(3)]
        self.api.terminal = True
        observations = len(self.api.observations)
        self.assertEqual(self.registry.reap(self.deadline(), max_ops=1).resources, 2)
        self.assertEqual(len(self.api.observations) - observations, 1)
        self.assertEqual(self.registry.reap(self.deadline(), max_ops=2).resources, 0)
        self.assertEqual(len(self.api.starts), 3)
        self.assertTrue(all(connection._closed for connection in connections))

    def test_verified_peer_scope_retains_exact_handle_and_blocks_close(self):
        listener = self.listener()
        connection = listener.accept(self.deadline())
        with connection.verified_peer(CLIENT) as process:
            self.assertEqual(process.identity, CLIENT)
            self.assertEqual(process.closes, 0)
            with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                connection.close()
            with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                listener.close()
            with self.assertRaisesRegex(native.NativePipeError, "^pipe_busy$"):
                with connection.verified_peer(CLIENT):
                    self.fail("second proof cannot acquire the same borrower")
            self.assertEqual(self.registry.status().resources, 1)
        self.assertEqual(process.closes, 1)
        connection.close()
        listener.close()

    def test_peer_proof_close_failure_retains_same_handle_until_successful_reap(self):
        listener = self.listener()
        connection = listener.accept(self.deadline())
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_peer_close_failed$"):
            with connection.verified_peer(CLIENT) as process:
                process.close_error = IdentityUnavailable("private-peer-close-detail", 5)
        self.assertIs(connection._owner._peer_process, process)
        self.assertEqual(self.registry.status(), native.PipeRegistryStatus(1, 0, 1))
        self.assertEqual(self.registry.reap(self.deadline()).resources, 1)
        self.assertIs(connection._owner._peer_process, process)
        self.assertEqual(process.closes, 0)
        process.close_error = None
        self.assertEqual(self.registry.reap(self.deadline()).resources, 0)
        self.assertEqual(process.closes, 1)

    def test_wrong_server_peer_fails_initialization_without_retaining_a_live_slot(self):
        self.api.peer_override = SERVER.pid + 1
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_server_identity_mismatch$"):
            self.client()
        self.assertEqual(self.registry.status().resources, 0)
        self.assertTrue(all(process.closes == 1 for process in self.processes))

    def test_invalid_deadlines_limits_and_sizes_issue_no_io(self):
        for timeout in (0, 5001, True, 1.5):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(native.NativePipeError, "pipe_deadline_invalid"):
                self.deadline(timeout)
        for maximum in (0, 129, True):
            with self.subTest(maximum=maximum), self.assertRaisesRegex(native.NativePipeError, "pipe_registry_limit_invalid"):
                native.NativePipeRegistry(maximum)
        connection = self.client()
        for size in (0, native.MAX_TRANSFER + 1, True):
            with self.subTest(size=size), self.assertRaisesRegex(native.NativePipeError, "pipe_size_invalid"):
                connection.read_exact(size, self.deadline())
        for payload in (b"", bytearray(b"x"), "private-body", b"x" * (native.MAX_TRANSFER + 1)):
            with self.subTest(type=type(payload).__name__), self.assertRaisesRegex(native.NativePipeError, "pipe_size_invalid"):
                connection.write_all(payload, self.deadline())
        self.assertEqual(self.api.starts, [])

    def test_deadline_rejects_clock_regression_and_foreign_process(self):
        deadline = self.deadline()
        self.api.now = 99
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_clock_invalid$"):
            deadline.require()
        self.api.now = 100.5
        with self.assertRaisesRegex(native.NativePipeError, "^pipe_clock_invalid$"):
            deadline.require()
        self.api.now = 100
        with patch.object(native.os, "getpid", return_value=SERVER.pid + 1):
            with self.assertRaisesRegex(native.NativePipeError, "^pipe_foreign_process$"):
                deadline.require()


class PortablePipeSecurityApiTests(unittest.TestCase):
    """Exercise API arguments without constructing a Windows DLL backend."""
    def setUp(self):
        self.endpoint = native.NativePipeEndpoint(LOGON, str(uuid4()), SERVER)

    def test_listener_creation_and_readback_use_pipe_rights_and_single_local_instance(self):
        backend = native._WindowsPipeBackend.__new__(native._WindowsPipeBackend)
        calls, freed, checked = [], [], []

        def descriptor(sddl, revision, target, size):
            calls.append(("sddl", sddl))
            ctypes.cast(target, ctypes.POINTER(ctypes.c_void_p)).contents.value = 321
            return True

        def create(*args):
            calls.append(("create", args))
            attributes = ctypes.cast(args[-1], ctypes.POINTER(native._security._SecurityAttributes)).contents
            self.assertFalse(attributes.inherit)
            return 123

        backend.security = SimpleNamespace(
            current_owner_sid=lambda: "S-1-5-21-1-2-3-1000",
            security=SimpleNamespace(ConvertStringSecurityDescriptorToSecurityDescriptorW=descriptor),
            free=freed.append, verify_security=lambda *args, **kwargs: checked.append((args, kwargs)))
        backend.kernel = SimpleNamespace(CreateNamedPipeW=create)
        owner = SimpleNamespace(_handle=None)
        self.assertEqual(backend.create_listener(self.endpoint, owner), 123)
        self.assertEqual(owner._handle, 123)
        self.assertEqual(calls[0][1], f"O:S-1-5-21-1-2-3-1000D:P(A;;0x0012019f;;;{LOGON})")
        args = calls[1][1]
        self.assertEqual(args[:4], (self.endpoint.name, 3 | 0x40000000 | 0x00080000, 8, 1))
        self.assertEqual(checked, [((123, LOGON, "S-1-5-21-1-2-3-1000"), {"access_mask": 0x0012019F})])
        self.assertNotEqual(checked[0][1]["access_mask"], native._security._ACCESS)
        self.assertEqual(len(freed), 1)

    def test_client_open_requests_data_rights_without_pipe_instance_creation_or_delegation(self):
        backend = native._WindowsPipeBackend.__new__(native._WindowsPipeBackend)
        calls = []
        backend.kernel = SimpleNamespace(CreateFileW=lambda *args: calls.append(args) or 123)
        with patch.object(native, "_backend", return_value=FixtureBackend()):
            deadline = native.NativeDeadline.after_ms(100)
        self.assertEqual(backend.open_client(self.endpoint, deadline), 123)
        self.assertEqual(len(calls), 1)
        args = calls[0]
        self.assertEqual(args[0], self.endpoint.name)
        self.assertEqual(args[1], 0x00120083)
        self.assertEqual(args[1] & 4, 0)
        self.assertNotEqual(args[1], native._security._ACCESS)
        self.assertEqual(args[5], 0x40000000 | 0x00100000 | 0x00010000)


if __name__ == "__main__":
    unittest.main()
