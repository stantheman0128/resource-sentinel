"""Original completed retirement evidence, with real isolated ledger writes.

The existing retirement fixture supplies synthetic native process/supervisor
owners. This module adds exact, already-settled readiness objects before the
original retirement constructor runs. No test activates a successor or claims
native Windows evidence.
"""
import copy
from dataclasses import replace
import gc
import hashlib
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4
import weakref

from sentinel.adaptive import daily_retirement as retirement
from sentinel.adaptive import daily_retirement_inventory as inventory
from sentinel.adaptive.daily_readiness_transport import DailyReadinessService
from sentinel.adaptive.daily_retirement_fence import DailyRetirementError
from sentinel.adaptive.pipe_windows import NativePipeListener, NativePipeRegistry, _PipeOwner
from sentinel.adaptive.policy import PolicyGuard
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor_host import _Guardian
from sentinel.adaptive.supervisor_startup import SupervisorStartup
from sentinel.adaptive.recovery_owner import RetainedGuardianCreation, _CREATION
from sentinel.adaptive.recovery_journal import RecoveryJournal
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_daily_retirement_integration as integration
from tests import test_adaptive_guardian_lifecycle as guardian_fixture
from tests import test_adaptive_terminal_receipt as terminal_fixture


class DailySuccessorPredecessorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integration.DailyRetirementIntegrationTests()
        self.addCleanup(self.fixture.doCleanups)
        original_factory = retirement.DailyRetirementOperation

        def prepare_original(host):
            # A real portable thread is positively joined. Pipe/native objects
            # are explicit fixtures and never invoke the Windows backend.
            thread = threading.Thread(target=lambda: None)
            thread.start()
            thread.join()
            registry = NativePipeRegistry(max_resources=1)
            native = object.__new__(_PipeOwner)
            native._registry = registry
            native.endpoint = host.owner.readiness_endpoint
            for name in ("_handle", "_operation", "_active", "_server_process",
                         "_self_process", "_peer_process", "_accept_operation", "_accept_connection"):
                setattr(native, name, None)
            native._handle_close_unknown = native._busy = native._poisoned = False
            native._proofs = 0
            listener = object.__new__(NativePipeListener)
            listener.endpoint, listener._owner = native.endpoint, native
            service = object.__new__(DailyReadinessService)
            service.endpoint, service.owner, service._process = native.endpoint, host.owner, host.owner.process
            host._thread, host._listener, host._registry, host._service = thread, listener, registry, service
            host._readiness_original_thread = thread
            host._readiness_original_listener = listener
            host._readiness_original_registry = registry
            host._thread_stopped, host._readiness_stop = threading.Event(), threading.Event()
            host._thread_stopped.set()
            host._readiness_stop.set()
            host._retirement_cleanup_error = host._readiness_failure = None
            host.supervisor.startup = SupervisorStartup(host.store, RecoveryJournal(host.journal_dir))
            host.supervisor.startup.close()  # Exact unentered fixture owner; no native factory.
            return original_factory(host)

        with patch.object(integration, "DailyRetirementOperation", side_effect=prepare_original):
            self.fixture.setUp()
        self.operation = self.fixture.operation

    def complete(self):
        frozen = self.fixture.freeze()
        self.operation.tick()
        self.fixture.assert_sealed(frozen)
        self.operation.close_owner()
        self.assertTrue(self.operation.complete)
        return self.operation

    def assert_refused(self):
        with self.assertRaises((DailyRetirementError, LifecycleError)):
            inventory.retired_inventory_preimage(self.operation)

    def test_actual_seal_retains_original_snapshot_before_mutation_and_after_gc(self):
        frozen = self.fixture.freeze()
        original_connect = sqlite3.connect
        observed = []
        operation = self.operation

        class ObserveSeal(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                if sql.startswith("UPDATE adaptive_daily_generation SET state='DRAINING'"):
                    snapshot = operation._seal_inventory
                    self.assertIs(type(snapshot), inventory.RetirementInventorySnapshot)
                    self.assertIs(operation._seal_inventory_pin[1], inventory._SNAPSHOTS[snapshot])
                    self.assertEqual(operation._seal_inventory_digest,
                                     inventory.retirement_inventory_digest(operation.store, snapshot))
                    observed.append(weakref.ref(snapshot))
                return super().execute(sql, parameters)

        def connect(*args, **kwargs):
            kwargs["factory"] = ObserveSeal
            return original_connect(*args, **kwargs)

        with patch.object(sqlite3, "connect", side_effect=connect):
            operation.tick()
        self.fixture.assert_sealed(frozen)
        self.assertEqual(len(observed), 1)
        gc.collect()
        self.assertIs(observed[0](), operation._seal_inventory)
        operation.close_owner()
        self.assertIsNone(operation.assert_successor_predecessor())
        ledger, receipts, journals = inventory.retired_inventory_preimage(operation)
        self.assertIs(type(ledger), bytes)
        self.assertIs(type(receipts), bytes)
        self.assertIs(type(journals), tuple)
        self.assertEqual(journals, ())
        digest = hashlib.sha256(b"resource-sentinel.daily-retirement-inventory.v1\x00")
        for value in (ledger, receipts):
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
        self.assertEqual(digest.hexdigest(), operation._seal_inventory_digest)

    def test_completed_preimage_performs_no_database_file_or_native_acquisition(self):
        operation = self.complete()
        expected = inventory.retired_inventory_preimage(operation)
        with (patch.object(sqlite3, "connect", side_effect=AssertionError("new SQL")),
              patch.object(Path, "open", side_effect=AssertionError("new file")),
              patch.object(operation.owner.process, "observe", side_effect=AssertionError("native query")),
              patch.object(operation.owner.process, "close", side_effect=AssertionError("native close")),
              patch.object(operation.supervisor, "_custody_snapshot", side_effect=AssertionError("new ledger read"))):
            self.assertEqual(inventory.retired_inventory_preimage(operation), expected)
            self.assertEqual(inventory.retired_inventory_preimage(operation), expected)
        self.assertIsNone(operation.policy.current_guard())

    def test_sealed_ledger_without_completed_original_native_cleanup_is_refused(self):
        frozen = self.fixture.freeze()
        self.operation.tick()
        self.fixture.assert_sealed(frozen)
        self.assert_refused()
        self.assertFalse(self.operation.complete)
        self.assertIsNotNone(self.operation.owner.process._handle)
        self.operation.close_owner()
        self.assertIsNone(self.operation.assert_successor_predecessor())

    def test_copied_operation_and_serialized_seal_cannot_supply_original_evidence(self):
        operation = self.complete()
        clone = copy.copy(operation)
        with self.assertRaisesRegex(DailyRetirementError, "original_retirement_required"):
            clone.assert_successor_predecessor()
        with self.assertRaisesRegex(LifecycleError, "completed_retirement_required"):
            inventory.retired_inventory_preimage(dict(operation._seal_row))
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_replaced_original_owners_and_readiness_objects_are_refused(self):
        operation = self.complete()
        for owner, name in ((operation, "store"), (operation, "supervisor"),
                (operation, "_freeze"), (operation, "_seal"), (operation, "journal"),
                (operation.owner, "process"), (operation.owner, "cohort"),
                (operation.host, "_listener"), (operation.host, "_registry"),
                (operation.host, "_service")):
            with self.subTest(name=name), patch.object(owner, name, copy.copy(getattr(owner, name))):
                self.assert_refused()
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_original_thread_and_pid_are_required_without_new_identity_lookup(self):
        operation = self.complete()
        with patch.object(retirement.os, "getpid", return_value=operation._pid + 1):
            self.assert_refused()
        with patch.object(retirement.threading, "current_thread", return_value=threading.Thread()):
            self.assert_refused()
        # Keep current_thread's real lookup from manufacturing a DummyThread
        # for the deliberately foreign identifier used by this refusal case.
        with (patch.object(retirement.threading, "current_thread", return_value=operation._thread),
              patch.object(retirement.threading, "get_ident", return_value=operation._thread_id + 1)):
            self.assert_refused()
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_unknown_original_sql_process_policy_or_readiness_custody_is_refused(self):
        operation = self.complete()
        self.assertTrue(operation.host._connections)
        connection = operation.host._connections[0]
        for owner, name, value in ((connection, "closed", False), (connection, "close_unknown", True),
                (connection, "connection", object()),
                (operation.owner.process, "_close_outcome_unknown", True),
                (operation.owner.cohort, "_closed", False),
                (operation._seal_guard, "_native_exit_confirmed", False),
                (operation._freeze_guard, "_nonce_clear_attempted", False),
                (operation.host, "_readiness_close_unknown", True),
                (operation.host._listener._owner, "_handle", 123),
                (operation, "_quarantine", "fixture_unknown")):
            with self.subTest(name=name), patch.object(owner, name, value):
                self.assert_refused()
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_retained_snapshot_row_and_digest_mutations_are_refused(self):
        operation = self.complete()
        snapshot = operation._seal_inventory
        original_capture = inventory._SNAPSHOTS[snapshot]
        with patch.object(operation, "_seal_inventory_digest", "0" * 64):
            self.assert_refused()
        with patch.object(operation, "_seal_row", dict(operation._seal_row)):
            self.assert_refused()
        value = operation._seal_row["seal_digest"]
        operation._seal_row["seal_digest"] = "0" * 64
        try:
            self.assert_refused()
        finally:
            operation._seal_row["seal_digest"] = value
        inventory._SNAPSHOTS[snapshot] = tuple(list(original_capture))
        try:
            self.assert_refused()
        finally:
            inventory._SNAPSHOTS[snapshot] = original_capture
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_distinct_new_guard_does_not_reuse_or_block_retired_old_guard(self):
        operation = self.complete()
        # This is only the thread-local marker inspected by the data reader;
        # no SQL mutation or authority is requested using this fixture guard.
        new_guard = PolicyGuard(operation._seal_guard.binding, str(uuid4()))
        operation.policy._held.guard = new_guard
        try:
            self.assertIsNone(operation.assert_successor_predecessor())
            operation.policy._held.guard = operation._seal_guard
            self.assert_refused()
        finally:
            operation.policy._held.guard = None
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_original_startup_owner_and_positive_close_flags_remain_bound(self):
        operation = self.complete()
        startup = operation.supervisor.startup
        with patch.object(operation.supervisor, "startup", copy.copy(startup)):
            self.assert_refused()
        for name, value in (("_closed", False), ("_close_unknown", True),
                ("_release_unknown", True), ("_entry_unknown", True), ("_mutex", object())):
            with self.subTest(name=name), patch.object(startup, name, value):
                self.assert_refused()
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_inner_child_creation_and_process_bindings_cannot_be_replaced(self):
        operation = self.operation
        process = self.fixture.backend.current()
        witness = RetainedGuardianCreation(_CREATION)
        witness._process, witness._guardian_epoch = process, "fixture-predecessor-child"
        child = _Guardian(epoch=witness._guardian_epoch, pid=process.identity.pid,
                          creation_handle=321, process=process, creation_witness=witness)
        witness.close()
        # Exact child is already closed in this explicit native fixture.
        operation.supervisor.retired = [child]
        operation.supervisor._closed_handles = {(id(child), "witness"), (id(child), "creation")}
        operation.supervisor._unknown_handles = set()
        operation.supervisor._drain_closed_children = {id(child)}
        self.complete()
        for owner, name, value in ((child, "creation_handle", 322),
                (child, "process", copy.copy(process)),
                (child, "creation_witness", copy.copy(witness)),
                (witness, "_process", copy.copy(process)),
                (process, "_close_outcome_unknown", True)):
            with self.subTest(name=name), patch.object(owner, name, value):
                self.assert_refused()
        self.assertIsNone(operation.assert_successor_predecessor())

    def test_real_terminal_manifest_preimage_preserves_execution_binding(self):
        # Add real terminal history AFTER the empty generation installation.
        # Cold installation over a preexisting terminal row remains forbidden.
        terminal = terminal_fixture.TerminalReceiptTests()
        self.addCleanup(terminal.doCleanups)
        terminal.directory, terminal.db = self.fixture.root, self.fixture.db
        terminal.policy = self.fixture.store._policy.provider
        terminal.setup_connections, terminal.seed_records = [], {}
        terminal.seed_store = LifecycleStore(terminal.db, policy_provider=terminal.policy,
            evidence_provider=fixture_evidence_provider(terminal.seed_evidence))
        terminal.store = terminal.seed_store
        terminal.processes = guardian_fixture.ProcessBackend()
        logon = self.fixture.process.identity.logon_id
        guardian = replace(guardian_fixture.GUARDIAN, logon_id=logon)
        terminal.guardian = terminal.processes.process(guardian)
        terminal.journal_dir = self.fixture.host.journal_dir
        terminal.journal = RecoveryJournal(terminal.journal_dir, publisher=guardian_fixture.publish_fixture)
        terminal.mutexes, terminal.cases, terminal.owner = [], [], None
        original_connection = terminal.connection

        def connection():
            conn = original_connection()
            integration.generation.prepare_connection(conn, role="coordinator", db_path=terminal.db)
            return conn

        terminal.connection = connection
        lifecycle = guardian_fixture.fixtures
        with (patch.object(guardian_fixture, "GUARDIAN", guardian),
              patch.object(lifecycle, "WRAPPER", replace(lifecycle.WRAPPER, logon_id=logon)),
              patch.object(lifecycle, "ROOT", replace(lifecycle.ROOT, logon_id=logon))):
            case = terminal.retired_case()
        # Fixture reader connections are explicitly closed before retirement.
        for conn in terminal.setup_connections:
            conn.close()
        expected = (terminal.journal_dir / (case.spec.execution_id + ".json")).read_bytes()
        operation = self.complete()
        ledger, receipts, journals = inventory.retired_inventory_preimage(operation)
        self.assertEqual(journals, ((case.spec.execution_id, expected),))
        self.assertIn(case.spec.execution_id.encode(), ledger)
        self.assertIn(case.spec.execution_id.encode(), receipts)
        records = inventory._SNAPSHOTS[operation._seal_inventory][8]
        record = records.pop(case.spec.execution_id)
        renamed = str(uuid4())
        records[renamed] = record
        try:
            with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                inventory.retired_inventory_preimage(operation)
        finally:
            records.pop(renamed)
            records[case.spec.execution_id] = record
        self.assertEqual(inventory.retired_inventory_preimage(operation)[2], journals)


if __name__ == "__main__":
    unittest.main()
