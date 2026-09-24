"""Real isolated admission + readiness protocol, explicit synthetic native I/O.

The process duplicate/close owners and client protocol are production paths.
The native backend, pipe exchange and source attestation are fixture seams;
these tests prove no Windows capability, measured overhead or P4 acceptance.
"""
from contextlib import closing, contextmanager, ExitStack
from copy import copy
import ctypes
import json
import os
import sqlite3
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import pipe_windows as pipe
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from tests import test_adaptive_experiment_demand as demand_tests
from tests import test_adaptive_managed_admission as managed_tests
from tests.test_adaptive_daily_readiness_lock_boundary import NativeIdentityFixture
from tests.test_adaptive_ipc import Clock, Connection
from tests.test_adaptive_pipe_windows import FixtureBackend as PipeBackend
from tests.windows import adaptive_daily_monitor as monitor_module


LOGON = "S-1-5-5-10-20"
_CONNECT = pipe.NativePipeConnection.connect


class _NativeFixture(NativeIdentityFixture):
    def __init__(self, identity, events):
        super().__init__(identity, events)
        self.copy_calls, self.close_calls = [], []
        self.after_copy = None
        self.fail_copy_number = None
        self.fail_copy = None
        self.close_errors = {}

    def duplicate_into(self, handle, output, *, source_process=None):
        self.copy_calls.append(handle)
        if len(self.copy_calls) == self.fail_copy_number:
            self.events.append("peer.duplicate")
            # Explicit FALSE has no output. Other failures model an uncertain
            # native invocation after an output cell might have been written.
            if not getattr(self.fail_copy, "_native_duplicate_failed", False):
                self.next_handle += 1
                output.value = self.next_handle
            raise self.fail_copy
        super().duplicate_into(handle, output, source_process=source_process)
        if self.after_copy:
            self.after_copy(len(self.copy_calls))

    def close(self, handle):
        self.close_calls.append(handle)
        error = self.close_errors.get(handle)
        if error is not None:
            raise error
        super().close(handle)


class DailyMonitorFixture(unittest.TestCase):
    """Reusable original capture; not itself a collection of test methods."""
    def setUp(self, *, suite="P4", admitted=True):
        self.events, self.clock = [], Clock()
        self.caller_identity = ProcessIdentity(os.getpid(), 134343072000000001, LOGON)
        self.keeper_identity = ProcessIdentity(os.getpid() + 10000, 134343072000000007, LOGON)
        self.caller_backend = _NativeFixture(self.caller_identity, self.events)
        self.keeper_backend = _NativeFixture(self.keeper_identity, self.events)
        self.caller = VerifiedProcess(self.caller_backend, 1, self.caller_identity)
        self.fixture = demand_tests.ExperimentDemandTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(managed_tests, "FakeCurrentProcess", return_value=self.caller):
            self.fixture.setUp()
        self.fixture.generation["owner_identity_json"] = demand_module._canonical(
            self.keeper_identity.to_dict())
        declaration = demand_module.ExperimentDeclaration(str(uuid4()), suite, "b" * 64,
            ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        self.demand = demand_module.DailyExperimentDemand.capture(declaration, self.fixture.scope)
        self.fixture.owners.append(self.demand)
        if admitted:
            self.result = self.fixture.coordinator.admit_experiment(self.demand)
            self.assertTrue(self.result["allowed"])
        self.connections, self.monitors = [], []
        self.reply_changes = {}
        self.pipe_cleanup_error = None
        self.addCleanup(self.cleanup_synthetic_owners)
        for replacement in (
                patch.object(monitor_module.generation, "verify_import_provenance"),
                patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock),
                patch.object(transport.NativePipeConnection, "connect", side_effect=self.connect)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def cleanup_synthetic_owners(self):
        # No real OS handle exists in these backends. A deliberately unknown
        # original remains unknown; remove only this fixture's retention roots
        # after assertions so they cannot accumulate across portable tests.
        owner = monitor_module._PENDING.get(id(self.demand))
        if owner is not None and owner.demand is self.demand:
            if owner._error is None and owner._cleanup_error is None:
                owner.close()
            monitor_module._PENDING.pop(id(self.demand), None)
        monitor_module._CAPTURED.pop(self.demand, None)
        self.caller_backend.close_errors.clear()
        self.caller.close()

    def connect(self, endpoint, deadline):
        test = self
        self.events.append("rpc")

        class SyntheticConnection(Connection):
            @contextmanager
            def verified_peer(self, expected):
                test.assertEqual(expected, test.keeper_identity)
                self.peer_held = True
                try:
                    yield self.retained
                finally:
                    self.peer_held = False
                    self.retained.close()

            def __exit__(self, *args):
                self.closed = True
                if test.pipe_cleanup_error is not None:
                    raise test.pipe_cleanup_error

        def respond(connection, message):
            if message["kind"] == "DailyReadinessAssert":
                connection.enqueue({"version": 1, "kind": "DailyReadinessReady",
                    "request_id": message["request_id"], "endpoint_id": endpoint.instance_id,
                    "server": endpoint.server_identity.to_dict(), "client": self.caller_identity.to_dict(),
                    "nonce": "c" * 64, **{name: message[name] for name in transport._BINDING_FIELDS},
                    **self.reply_changes})

        connection = SyntheticConnection(self.keeper_identity, on_write=respond)
        connection.retained = VerifiedProcess(self.keeper_backend, 2, self.keeper_identity)
        self.connections.append(connection)
        return connection

    def capture(self):
        value = monitor_module.DailyMonitorWitness.capture(self.demand)
        self.monitors.append(value)
        return value

    def release_original_demand(self):
        """Actual original BEFORE_NATIVE release, no new admission or RPC."""
        completion = self.demand.seal_without_native()
        operation = self.demand.prepare_release(completion)
        self.addCleanup(lambda: cleanup._OPERATIONS.pop(operation.operation_id, None))
        with closing(sqlite3.connect(self.demand.ledger_path)) as conn:
            row = self.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for unused in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        with ExitStack() as stack:
            stack.enter_context(patch.object(generation, "_assert_daily_locations"))
            stack.enter_context(patch.object(generation, "verify_import_provenance"))
            stack.enter_context(patch.object(generation, "_prove_retained_owner_ready",
                side_effect=AssertionError("release requested a fresh readiness RPC")))
            return self.fixture.coordinator.release_experiment(operation)

    @contextmanager
    def actual_pipe(self, *, unknown_close=False):
        """Real pipe owner/connection/protocol, explicitly synthetic kernel."""
        fixture, registry, resources = self, pipe.NativePipeRegistry(), {}

        class Backend(PipeBackend):
            def __init__(self):
                super().__init__()
                self.peer_override = fixture.keeper_identity.pid
                self.fail_close = True

            def start(self, handle, operation):
                if operation.kind == "write":
                    wire = ctypes.string_at(operation.buffer, operation.size)
                    request = json.loads(wire[4:])
                    if request["kind"] == "DailyReadinessAssert":
                        reply = {"version": 1, "kind": "DailyReadinessReady",
                            "request_id": request["request_id"],
                            "endpoint_id": fixture.fixture.generation["readiness_instance_id"],
                            "server": fixture.keeper_identity.to_dict(), "client": fixture.caller_identity.to_dict(),
                            "nonce": "c" * 64, **{name: request[name] for name in transport._BINDING_FIELDS}}
                        payload = json.dumps(reply, separators=(",", ":")).encode()
                        self.read_data.extend(struct.pack("<I", len(payload)) + payload)
                super().start(handle, operation)

            def close(self, handle):
                if self.handles[handle] == "client" and self.fail_close:
                    self.close_attempts.append(handle)
                    if unknown_close:
                        raise OSError("synthetic_native_pipe_close_unknown")
                    raise pipe._NativeCloseFailed("pipe_handle_close_failed", 6)
                super().close(handle)

        api, processes = Backend(), []

        def process(identity):
            backend = self.caller_backend if identity == self.caller_identity else self.keeper_backend
            result = VerifiedProcess(backend, 500 + len(processes), identity)
            processes.append(result)
            return result

        def connect(endpoint, deadline):
            self.events.append("rpc")
            return _CONNECT(endpoint, deadline, registry)

        with ExitStack() as stack:
            stack.enter_context(patch.object(pipe, "_backend", return_value=api))
            stack.enter_context(patch.object(pipe, "_PROCESS_RESOURCES", resources))
            stack.enter_context(patch.object(pipe.VerifiedProcess, "current",
                side_effect=lambda: process(self.caller_identity)))
            stack.enter_context(patch.object(pipe.VerifiedProcess, "open", side_effect=process))
            stack.enter_context(patch.object(pipe.NativePipeConnection, "connect", side_effect=connect))
            yield api, registry, resources
        # Unknown simulated handles remain unknown. These local registry and
        # backend objects represent no OS resources; no successful native
        # cleanup or production release is invented in fixture teardown.


class DailyMonitorTests(unittest.TestCase):
    def fixture(self, **kwargs):
        fixture = DailyMonitorFixture()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp(**kwargs)
        return fixture

    def test_capture_authenticates_pinned_daily_owner_and_owns_separate_cost_handle(self):
        fixture = self.fixture()
        before = fixture.fixture.assert_retained(fixture.demand)
        owner = fixture.capture()
        witness = owner.assert_original()
        self.assertIs(type(witness), VerifiedProcess)
        self.assertEqual(witness.identity, fixture.keeper_identity)
        self.assertIsNot(witness, fixture.caller)
        self.assertEqual(fixture.keeper_backend.copy_calls, [2, 11])
        self.assertEqual(witness._handle, 12)
        self.assertTrue(owner._authority._closed)
        self.assertIsNone(owner._authority._peer._handle)
        self.assertEqual(before, fixture.fixture.assert_retained(fixture.demand))
        request = fixture.connections[0].writes[-1]
        row = fixture.fixture.generation
        self.assertEqual(request["generation"], row["generation"])
        self.assertEqual(request["source_digest"], row["source_digest"])
        self.assertEqual(request["config_digest"], row["config_digest"])
        self.assertEqual(request["ledger_identity"], owner._binding["ledger_identity"])
        monitor_module.generation.verify_import_provenance.assert_called_once()
        owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertEqual(before, fixture.fixture.assert_retained(fixture.demand))

    def test_cost_witness_does_not_extend_readiness_deadline_or_reacquire(self):
        fixture = self.fixture(suite="S2")
        owner = fixture.capture()
        witness = owner.assert_original()
        fixture.clock.now += 2000
        self.assertIs(owner.assert_original(), witness)
        with self.assertRaisesRegex(transport.DailyReadinessError, "authority_unavailable"):
            owner._authority.revalidate(owner.endpoint, owner._binding)
        owner.close()
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_unadmitted_and_wrong_suite_refuse_before_rpc(self):
        for kwargs in ({"admitted": False}, {"suite": "S1"}):
            with self.subTest(kwargs=kwargs):
                fixture = self.fixture(**kwargs)
                with self.assertRaises(RuntimeError):
                    fixture.capture()
                self.assertEqual(fixture.connections, [])

    def test_copy_and_untyped_demand_cannot_capture(self):
        fixture = self.fixture()
        for value in (copy(fixture.demand), SimpleNamespace(), {}):
            with self.subTest(type=type(value).__name__), self.assertRaises(RuntimeError):
                monitor_module.DailyMonitorWitness.capture(value)
        self.assertEqual(fixture.connections, [])

    def test_preparation_or_seal_prevents_late_capture(self):
        fixture = self.fixture()
        for name, value in (("_native_preparation", object()), ("_native_preparation_sealed", True)):
            with self.subTest(name=name), patch.object(fixture.demand, name, value):
                with self.assertRaisesRegex(monitor_module.DailyMonitorError, "before_fixture"):
                    fixture.capture()
        self.assertEqual(fixture.connections, [])

    def test_capture_refuses_under_native_policy_or_job_lock(self):
        fixture = self.fixture()
        with patch.object(monitor_module, "current_thread_holds_mutex", return_value=True):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "lock_held"):
                fixture.capture()
        self.assertEqual(fixture.connections, [])

    def test_reply_binding_mismatch_never_issues_cost_witness(self):
        fixture = self.fixture()
        fixture.reply_changes["generation"] = str(uuid4())
        with self.assertRaisesRegex(transport.DailyReadinessError, "reply_mismatch") as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        self.assertIs(owner._error, caught.exception)
        self.assertIs(owner._error_connection, fixture.connections[0])
        self.assertIsNone(owner._witness)
        self.assertTrue(owner.custody_pending)
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "witness_unavailable"):
            owner.assert_original()
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "already_exists"):
            fixture.capture()

    def test_deadline_expiry_after_actual_cost_duplicate_retains_then_closes_same_copy(self):
        fixture = self.fixture()
        fixture.keeper_backend.after_copy = lambda count: (
            setattr(fixture.clock, "now", fixture.clock.now + 1000) if count == 2 else None)
        with self.assertRaisesRegex(RuntimeError, "pipe_timeout") as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        self.assertIs(owner._witness, owner._witness_pin)
        self.assertEqual(owner._witness._handle, 12)
        self.assertTrue(owner.custody_pending)
        owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertEqual(fixture.keeper_backend.close_calls.count(12), 1)
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_failed_rpc_cleanup_keeps_original_transport_error_and_refuses_replacement(self):
        fixture = self.fixture()
        primary = OSError("synthetic_pipe_close_unknown")
        fixture.pipe_cleanup_error = primary
        with self.assertRaises(transport.DailyReadinessError) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        self.assertIs(caught.exception._daily_readiness_cause, primary)
        self.assertIs(owner._error_connection, fixture.connections[0])
        self.assertTrue(owner._authority._closed)
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "rpc_custody_unsettled"):
            owner.close()
        # A foreign object's `closed` field cannot acknowledge original custody.
        caught.exception._daily_readiness_connection = SimpleNamespace(_closed=True)
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "rpc_custody_unsettled"):
            owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_actual_native_connection_known_false_closes_only_original_transport(self):
        fixture = self.fixture()
        with fixture.actual_pipe() as (api, unused_registry, resources):
            with self.assertRaises(transport.DailyReadinessError) as caught:
                fixture.capture()
            owner = caught.exception.daily_monitor_owner
            connection = owner._error_connection
            self.assertIs(type(connection), pipe.NativePipeConnection)
            self.assertIs(connection._owner, owner._error_connection_owner)
            handle = connection._owner._handle
            self.assertIs(connection._owner._handle_close_unknown, False)
            self.assertTrue(owner.custody_pending)
            api.fail_close = False
            owner.close()
            self.assertFalse(owner.custody_pending)
            self.assertTrue(connection._closed)
            self.assertEqual(api.close_attempts.count(handle), 2)
            self.assertEqual(resources, {})
            self.assertEqual(fixture.events.count("rpc"), 1)

    def test_actual_native_connection_unknown_close_is_not_retried(self):
        fixture = self.fixture()
        with fixture.actual_pipe(unknown_close=True) as (api, unused_registry, resources):
            with self.assertRaises(transport.DailyReadinessError) as caught:
                fixture.capture()
            owner = caught.exception.daily_monitor_owner
            original = owner._error_connection_owner
            handle = original._handle
            self.assertIs(resources.get(id(original)), original)
            self.assertIs(original._handle_close_unknown, True)
            api.fail_close = False
            with self.assertRaisesRegex(pipe.NativePipeError, "pipe_handle_close_unknown"):
                owner.close()
            self.assertTrue(owner.custody_pending)
            self.assertIs(owner._error_connection._owner, original)
            self.assertEqual(api.close_attempts.count(handle), 1)
            self.assertEqual(fixture.events.count("rpc"), 1)

    def test_unknown_duplicate_retains_original_output_owner_and_never_retries_native(self):
        fixture = self.fixture()
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = OSError("synthetic_duplicate_unknown")
        with self.assertRaises(OSError) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        original = caught.exception._identity_handle_cleanup[0]
        self.assertIs(owner._error_owners[0][1][0], original)
        for unused in range(2):
            with self.assertRaisesRegex(IdentityUnavailable, "duplicate_outcome_unknown"):
                owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertEqual(len(fixture.keeper_backend.copy_calls), 2)
        self.assertNotIn(12, fixture.keeper_backend.close_calls)

    def test_erased_original_duplicate_cleanup_cannot_be_acknowledged(self):
        fixture = self.fixture()
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = OSError("synthetic_duplicate_unknown")
        with self.assertRaises(OSError) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        original = caught.exception._identity_handle_cleanup[0]
        caught.exception._identity_handle_cleanup = ()
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "cleanup_owner_changed"):
            owner.close()
        self.assertIs(owner._error_owners[0][1][0], original)
        caught.exception._identity_handle_cleanup = (original,)
        self.assertTrue(owner.custody_pending)

    def test_known_duplicate_false_with_no_output_has_no_uncertain_handle(self):
        fixture = self.fixture()
        error = IdentityUnavailable("process_duplicate_failed", 5)
        error._native_duplicate_failed = True
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = error
        with self.assertRaises(IdentityUnavailable) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertIsNone(owner._witness)
        self.assertEqual(fixture.keeper_backend.copy_calls, [2, 11])

    def test_ambient_exception_context_does_not_authorize_foreign_cleanup(self):
        fixture = self.fixture()
        foreign_identity = ProcessIdentity(os.getpid() + 20000, 134343072000000099, LOGON)
        foreign_backend = _NativeFixture(foreign_identity, [])
        foreign = VerifiedProcess(foreign_backend, 99, foreign_identity)
        self.addCleanup(foreign.close)
        ambient = OSError("unrelated_pending_operation")
        ambient._identity_handle_cleanup = (foreign,)
        error = IdentityUnavailable("process_duplicate_failed", 5)
        error._native_duplicate_failed = True
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = error
        try:
            raise ambient
        except OSError:
            with self.assertRaises(IdentityUnavailable) as caught:
                fixture.capture()
        owner = caught.exception.daily_monitor_owner
        self.assertIs(caught.exception.__context__, ambient)
        owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertEqual(foreign._handle, 99)
        self.assertEqual(foreign_backend.close_calls, [])
        self.assertEqual(ambient._identity_handle_cleanup, (foreign,))

    def test_known_false_close_retries_only_original_witness(self):
        fixture = self.fixture()
        owner = fixture.capture()
        original = owner.assert_original()
        fixture.keeper_backend.close_errors[12] = IdentityUnavailable("process_handle_close_failed", 5)
        with self.assertRaises(IdentityUnavailable):
            owner.close()
        self.assertTrue(owner.custody_pending)
        del fixture.keeper_backend.close_errors[12]
        owner.close()
        owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertIs(owner._witness, original)
        self.assertEqual(fixture.keeper_backend.close_calls.count(12), 2)
        self.assertEqual(fixture.events.count("rpc"), 1)
        self.assertEqual(len(fixture.keeper_backend.copy_calls), 2)

    def test_unknown_witness_close_remains_pending_without_second_native_close(self):
        fixture = self.fixture()
        owner = fixture.capture()
        fixture.keeper_backend.close_errors[12] = OSError("synthetic_close_unknown")
        with self.assertRaises(OSError):
            owner.close()
        del fixture.keeper_backend.close_errors[12]
        with self.assertRaisesRegex(IdentityUnavailable, "close_outcome_unknown"):
            owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertEqual(fixture.keeper_backend.close_calls.count(12), 1)

    def test_replacement_handle_and_nonoriginal_monitor_refuse(self):
        fixture = self.fixture()
        owner = fixture.capture()
        original = owner.assert_original()
        with self.assertRaises(TypeError):
            copy(owner)
        replacement = VerifiedProcess(fixture.keeper_backend, 99, fixture.keeper_identity)
        with patch.object(owner, "_witness", replacement):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_binding_changed"):
                owner.assert_original()
        self.assertIs(owner.assert_original(), original)
        owner.close()
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "already_exists"):
            fixture.capture()

    def test_mutating_both_local_witness_references_does_not_replace_captured_owner(self):
        fixture = self.fixture()
        owner = fixture.capture()
        replacement = VerifiedProcess(fixture.keeper_backend, 99, fixture.keeper_identity)
        with patch.object(owner, "_witness", replacement), patch.object(owner, "_witness_pin", replacement):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_outcome_changed"):
                owner.close()
        self.assertNotIn(99, fixture.keeper_backend.close_calls)
        self.assertTrue(owner.custody_pending)
        owner.close()

    def test_same_process_wrapper_cannot_substitute_native_handle_backend_or_lock(self):
        fixture = self.fixture()
        owner = fixture.capture()
        witness = owner.assert_original()
        before = list(fixture.keeper_backend.close_calls)
        foreign_backend = _NativeFixture(fixture.keeper_identity, [])
        for name, replacement in (("_handle", 99), ("_backend", foreign_backend), ("_lock", threading.Lock())):
            with self.subTest(name=name), patch.object(witness, name, replacement):
                with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_native_custody_changed"):
                    owner.assert_original()
                with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_native_custody_changed"):
                    owner.close()
        self.assertEqual(fixture.keeper_backend.close_calls, before)
        self.assertEqual(foreign_backend.close_calls, [])
        owner.close()
        self.assertEqual(fixture.keeper_backend.close_calls.count(12), 1)

    def test_completed_native_ack_cannot_be_reopened_by_mutating_same_wrapper(self):
        fixture = self.fixture()
        owner = fixture.capture()
        witness = owner.assert_original()
        owner.close()
        with patch.object(witness, "_handle", 99):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_native_custody_changed"):
                owner.custody_pending
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_native_custody_changed"):
                owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertNotIn(99, fixture.keeper_backend.close_calls)

    def test_unknown_duplicate_output_cell_cannot_be_substituted_during_cleanup(self):
        fixture = self.fixture()
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = OSError("synthetic_duplicate_unknown")
        with self.assertRaises(OSError) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        original = caught.exception._identity_handle_cleanup[0]
        with patch.object(original, "_output", ctypes.c_void_p(original._output.value)):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_native_custody_changed"):
                owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertNotIn(12, fixture.keeper_backend.close_calls)

    def test_unknown_native_close_state_cannot_be_erased_on_the_process_wrapper(self):
        fixture = self.fixture()
        owner = fixture.capture()
        witness = owner.assert_original()
        fixture.keeper_backend.close_errors[12] = OSError("synthetic_close_unknown")
        with self.assertRaises(OSError):
            owner.close()
        with patch.object(witness, "_close_outcome_unknown", False):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "native_cleanup_unverified"):
                owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertEqual(fixture.keeper_backend.close_calls.count(12), 1)

    def test_replacing_error_and_cleanup_tuple_does_not_discard_original_unknown(self):
        fixture = self.fixture()
        fixture.keeper_backend.fail_copy_number = 2
        fixture.keeper_backend.fail_copy = OSError("synthetic_duplicate_unknown")
        with self.assertRaises(OSError) as caught:
            fixture.capture()
        owner = caught.exception.daily_monitor_owner
        with patch.object(owner, "_error", OSError("replacement")), patch.object(owner, "_error_owners", ()):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_outcome_changed"):
                owner.close()
        self.assertTrue(owner.custody_pending)

    def test_capture_flags_are_exact_booleans(self):
        fixture = self.fixture()
        owner = fixture.capture()
        with patch.object(owner, "_rpc_returned", 1):
            with self.assertRaisesRegex(monitor_module.DailyMonitorError, "original_outcome_changed"):
                owner.assert_original()
        owner.close()

    def test_positive_close_interrupted_local_finish_replays_without_native_calls(self):
        fixture = self.fixture()
        owner = fixture.capture()
        assign = monitor_module.DailyMonitorWitness.__setattr__
        interrupted = []

        def interrupt(this, name, value):
            if this is owner and name == "_closed" and value is True and not interrupted:
                interrupted.append(True)
                raise KeyboardInterrupt("synthetic_local_close_ack_loss")
            assign(this, name, value)

        with patch.object(monitor_module.DailyMonitorWitness, "__setattr__", interrupt):
            with self.assertRaises(KeyboardInterrupt):
                owner.close()
        self.assertTrue(owner.custody_pending)
        self.assertIsNone(owner._witness._handle)
        before = list(fixture.keeper_backend.close_calls)
        with patch.object(fixture.keeper_backend, "close", side_effect=AssertionError("native close replayed")):
            owner.close()
        self.assertFalse(owner.custody_pending)
        self.assertEqual(fixture.keeper_backend.close_calls, before)
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_closed_monitor_remains_verifiable_after_actual_original_demand_release(self):
        fixture = self.fixture()
        owner = fixture.capture()
        owner.close()
        result = fixture.release_original_demand()
        self.assertTrue(result["released"])
        self.assertTrue(fixture.demand._closed)
        self.assertIsNone(fixture.demand._admission._snapshot)
        self.assertIsNone(fixture.caller._handle)
        with patch.object(fixture.keeper_backend, "close", side_effect=AssertionError("native close replayed")):
            self.assertFalse(owner.custody_pending)
            owner.close()
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "witness_unavailable"):
            owner.assert_original()
        self.assertEqual(fixture.events.count("rpc"), 1)

    def test_dead_or_unknown_keeper_is_never_credited_as_zero_cost(self):
        fixture = self.fixture()
        owner = fixture.capture()
        fixture.keeper_backend.status = IdentityStatus.DEAD
        with self.assertRaisesRegex(monitor_module.DailyMonitorError, "identity_unverified"):
            owner.assert_original()
        owner.close()


if __name__ == "__main__":
    unittest.main()
