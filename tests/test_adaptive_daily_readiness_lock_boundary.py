"""Synthetic original-pipe custody and real isolated SQL; no native acceptance."""
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel import coordinator, maintainer
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive import windows
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.policy import PolicyCoordinator
from sentinel.adaptive.store import LifecycleStore
from sentinel.adaptive.experiment_scope import _IsolatedStore
from tests.test_adaptive_daily_generation import DailyGenerationTests
from tests.test_adaptive_ipc import Clock, Connection


class NativeIdentityFixture:
    """Limited process handles with actual production duplicate/close owners."""
    def __init__(self, identity, events):
        self.identity_value, self.events = identity, events
        self.status = IdentityStatus.ALIVE
        self.next_handle = 10
        self.close_error = None
        self.duplicate_error = None
        self.closed = []

    def identity(self, handle):
        return self.identity_value

    def wait(self, handle):
        if self.status is IdentityStatus.UNKNOWN:
            raise IdentityUnavailable("fixture_identity_unknown")
        return self.status

    def duplicate_into(self, handle, output, *, source_process=None):
        self.events.append("peer.duplicate")
        self.next_handle += 1
        output.value = self.next_handle
        if self.duplicate_error:
            raise self.duplicate_error

    def close(self, handle):
        self.events.append("peer.close" if handle >= 10 else "caller.close")
        if self.close_error:
            raise self.close_error
        self.closed.append(handle)


class PolicyFixture:
    def __init__(self, logon, events):
        self.logon, self.events = logon, events
        self.active = False
        self.on_enter = None
        self.on_exit = None

    def current_logon(self):
        return self.logon

    @contextmanager
    def hold(self, binding, *, timeout_ms):
        self.events.append("policy.enter")
        self.active = True
        try:
            if self.on_enter:
                self.on_enter()
            yield windows.PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, False)
        finally:
            self.events.append("policy.exit")
            self.active = False
            if self.on_exit:
                self.on_exit()


class DailyReadinessLockBoundaryTests(unittest.TestCase):
    install = DailyGenerationTests.install

    def setUp(self):
        DailyGenerationTests.setUp(self)
        self.install()
        generation._LOCAL_GENERATIONS.pop(self.owner.generation)
        for column, definition in (
                ("schema_version", "INTEGER DEFAULT 1"),
                ("protocol_version", "INTEGER DEFAULT 1"),
                ("registry_revision", "INTEGER DEFAULT 0"),
                ("policy_binding_initialized", "INTEGER DEFAULT 1"),
                ("active_logon_id", "TEXT DEFAULT ''")):
            self.conn.execute(f"ALTER TABLE adaptive_runtime ADD COLUMN {column} {definition}")
        self.conn.execute("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
        self.conn.commit()
        self.events, self.clock = [], Clock()
        self.provider = PolicyFixture(self.identity.logon_id, self.events)
        self.store = LifecycleStore.__new__(LifecycleStore)
        self.store.db_path, self.store._existing_ledger_path = self.db, None
        self.store.existing_path = False
        self.store._policy = PolicyCoordinator(self.store, self.provider)
        self.server_backend = NativeIdentityFixture(self.identity, self.events)
        self.caller_identity = ProcessIdentity(os.getpid(), 123456789, self.identity.logon_id)
        self.caller_backend = NativeIdentityFixture(self.caller_identity, self.events)
        self.connections = []
        self.reply_changes = {}
        self.rpc_callback = None
        self.peer_cleanup_error = None
        self.pipe_cleanup_error = None
        self.addCleanup(self.clear_owned_scopes)
        replacements = (
            patch.object(generation, "verify_import_provenance",
                         side_effect=lambda manifest, root: manifest.verify(root)),
            patch.object(generation.VerifiedProcess, "current", side_effect=self.current),
            patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock),
            patch.object(transport.NativePipeConnection, "connect", side_effect=self.connect),
        )
        for replacement in replacements:
            replacement.start()
            self.addCleanup(replacement.stop)

    def clear_owned_scopes(self):
        # Only synthetic owners for this test's unique temporary ledger.
        with generation._READINESS_SCOPES_LOCK:
            for pool in (generation._READINESS_SCOPES, generation._ABSENCE_SCOPES):
                for key, scope in tuple(pool.items()):
                    if scope.path.parent == self.root.resolve():
                        if scope.reader is not None and scope.reader.connection is not None and not scope.reader.closed:
                            # Tests may deliberately fail before the real SQLite
                            # close call; release that known synthetic fixture leak.
                            scope.reader.connection.close()
                        pool.pop(key)

    def current(self):
        return VerifiedProcess(self.caller_backend, 1, self.caller_identity)

    def connect(self, endpoint, deadline):
        self.assertFalse(self.provider.active, "readiness RPC occurred under POLICY")
        self.assertFalse(self.conn.in_transaction, "fixture SQL lock held during RPC")
        # An independent writer proves no LifecycleStore SQL lock survived.
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as probe:
            probe.execute("BEGIN IMMEDIATE")
            probe.rollback()
        self.events.append("rpc")
        test = self

        class OriginalPeerConnection(Connection):
            @contextmanager
            def verified_peer(self, expected):
                test.assertEqual(expected, test.identity)
                self.peer_held = True
                try:
                    yield self.retained
                finally:
                    self.peer_held = False
                    test.events.append("pipe.peer.close")
                    self.retained.close()
                    if test.peer_cleanup_error:
                        raise test.peer_cleanup_error

            def __exit__(self, *args):
                self.closed = True
                test.events.append("pipe.close")
                if test.pipe_cleanup_error:
                    raise test.pipe_cleanup_error

        def respond(connection, message):
            if message["kind"] == "DailyReadinessAssert":
                if self.rpc_callback:
                    self.rpc_callback()
                connection.enqueue({"version": 1, "kind": "DailyReadinessReady",
                    "request_id": message["request_id"], "endpoint_id": endpoint.instance_id,
                    "server": endpoint.server_identity.to_dict(), "client": self.caller_identity.to_dict(),
                    "nonce": "c" * 64, **{name: message[name] for name in transport._BINDING_FIELDS},
                    **self.reply_changes})
        connection = OriginalPeerConnection(self.identity, on_write=respond)
        connection.retained = VerifiedProcess(self.server_backend, 2, self.identity)
        self.connections.append(connection)
        return connection

    def bind(self, connection, role="lifecycle"):
        return generation.prepare_connection(connection, role=role, db_path=self.db)

    def change(self, field, value):
        self.conn.execute("UPDATE adaptive_daily_generation SET " + field + "=?", (value,))
        self.conn.commit()

    def isolated_store(self):
        isolated = _IsolatedStore(self.root / "isolated.sqlite3")
        isolated._policy = PolicyCoordinator(isolated, PolicyFixture(self.identity.logon_id, self.events))
        return isolated

    def test_policy_initial_and_nested_connections_share_original_prelock_authority(self):
        guard = self.store._policy.prepare(self.identity.logon_id)
        self.events.clear()
        with self.store._policy.hold(guard):
            with self.store._transaction() as conn:
                conn.execute("INSERT INTO reservations VALUES('one')")
            with self.store._connection() as conn:
                self.bind(conn, "legacy_writer")
            for cls in (coordinator.Coordinator, maintainer.Maintainer):
                instance = cls.__new__(cls)
                instance.db_path = self.db
                with instance._db() as conn:
                    conn.execute("SELECT sentinel_daily_generation()")
        self.assertEqual(self.events.count("rpc"), 1)
        self.assertLess(self.events.index("rpc"), self.events.index("policy.enter"))
        self.assertLess(self.events.index("pipe.close"), self.events.index("policy.enter"))
        self.assertEqual(self.events[-1], "peer.close")
        self.assertIsNone(self.conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_capacity_consumers_hold_scope_through_sql(self):
        for cls in (coordinator.Coordinator, maintainer.Maintainer):
            with self.subTest(consumer=cls.__name__):
                instance = cls.__new__(cls)
                instance.db_path = self.db
                with instance._db() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("INSERT INTO queue VALUES(?)", (cls.__name__,))
                    conn.commit()
                self.assertTrue(self.connections[-1].closed)

    def test_scope_cannot_authorize_later_connection_or_write(self):
        with generation.readiness_scope(self.db):
            self.bind(self.conn)
        with self.assertRaises(sqlite3.OperationalError):
            self.conn.execute("INSERT INTO reservations VALUES('late')")
        self.conn.rollback()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_required"):
            self.bind(self.conn)

    def test_local_owner_scoped_udf_cannot_outlive_original_scope(self):
        with patch.dict(generation._LOCAL_GENERATIONS, {self.owner.generation: self.owner}):
            with generation.readiness_scope(self.db):
                self.bind(self.conn)
                self.conn.execute("INSERT INTO reservations VALUES('local-within-scope')")
                self.conn.commit()
            with self.assertRaises(sqlite3.OperationalError):
                self.conn.execute("INSERT INTO reservations VALUES('local-after-scope')")
            self.conn.rollback()
        self.assertEqual(self.events.count("rpc"), 0)

    def test_initial_absence_cannot_promote_to_active_local_capacity(self):
        schema = self.conn.execute("SELECT sql FROM sqlite_master WHERE type='table' "
                                   "AND name='adaptive_daily_generation'").fetchone()[0]
        self.conn.execute("CREATE TEMP TABLE original_generation AS SELECT * FROM adaptive_daily_generation")
        self.conn.execute("DROP TABLE adaptive_daily_generation")
        self.conn.commit()
        with patch.dict(generation._LOCAL_GENERATIONS, {self.owner.generation: self.owner}):
            with generation.readiness_scope(self.db) as original:
                self.assertIsNone(original.row)
                self.conn.execute(schema)
                self.conn.execute("INSERT INTO adaptive_daily_generation SELECT * FROM original_generation")
                self.conn.commit()
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_binding_changed"):
                    self.bind(self.conn)
        self.assertEqual(self.events.count("rpc"), 0)

    def test_scope_is_not_refreshed_by_nested_connections(self):
        with generation.readiness_scope(self.db) as outer:
            self.clock.now += 999
            with generation.readiness_scope(self.db) as inner:
                self.assertIs(inner, outer)
                self.bind(self.conn)
                self.clock.now += 1
                with self.assertRaises(sqlite3.OperationalError):
                    self.conn.execute("INSERT INTO reservations VALUES('expired')")
                self.conn.rollback()
        self.assertEqual(self.events.count("rpc"), 1)

    def test_wait_expiration_rejects_before_policy_yield(self):
        guard = self.store._policy.prepare(self.identity.logon_id)
        self.provider.on_enter = lambda: setattr(self.clock, "now", self.clock.now + 1000)
        with self.assertRaisesRegex(Exception, "pipe_timeout"):
            with self.store._policy.hold(guard):
                self.fail("expired authority reached consumer")
        self.assertFalse(self.provider.active)
        self.assertIsNotNone(self.conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_expired_successful_operation_can_only_clear_original_nonce(self):
        guard = self.store._policy.prepare(self.identity.logon_id)
        with self.store._policy.hold(guard):
            self.clock.now += 1000
        self.assertIsNone(self.conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_generation_and_endpoint_changes_after_rpc_fail_before_policy_yield(self):
        for field, value in (("generation", str(uuid4())), ("readiness_instance_id", str(uuid4())),
                             ("state", "DRAINING")):
            with self.subTest(field=field):
                original = self.conn.execute("SELECT " + field + " FROM adaptive_daily_generation").fetchone()[0]
                guard = self.store._policy.prepare(self.identity.logon_id)
                self.provider.on_enter = lambda: self.change(field, value)
                with self.assertRaises(generation.DailyGenerationUnavailable):
                    with self.store._policy.hold(guard):
                        self.fail("changed generation reached consumer")
                self.change(field, original)
                self.provider.on_enter = None
                # Explicit fixture repair, never production nonce adoption.
                self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
                self.conn.commit()

    def test_generation_disappearance_is_not_absent_generation_fallback(self):
        with generation.readiness_scope(self.db):
            self.conn.execute("DROP TABLE adaptive_daily_generation")
            self.conn.commit()
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_changed"):
                self.bind(self.conn)

    def test_begin_revalidates_original_witness_without_rpc(self):
        with generation.readiness_scope(self.db):
            self.bind(self.conn)
            self.conn.execute("BEGIN IMMEDIATE")
            self.server_backend.status = IdentityStatus.DEAD
            with self.assertRaises(sqlite3.OperationalError):
                generation.revalidate_transaction(self.conn, db_path=self.db)
            self.conn.rollback()
        self.assertEqual(self.events.count("rpc"), 1)

    def test_source_config_ledger_and_witness_changes_at_write_fail(self):
        changes = (
            lambda: (self.root / "config.json").write_text("{}"),
            lambda: (self.root / "sentinel/coordinator.py").write_text("# changed\n"),
            lambda: setattr(self.server_backend, "status", IdentityStatus.DEAD),
            lambda: setattr(self.server_backend, "status", IdentityStatus.UNKNOWN),
        )
        original_config = (self.root / "config.json").read_bytes()
        original_source = (self.root / "sentinel/coordinator.py").read_bytes()
        for change in changes:
            with self.subTest(change=change):
                with generation.readiness_scope(self.db):
                    self.bind(self.conn)
                    change()
                    with self.assertRaises(sqlite3.OperationalError):
                        self.conn.execute("INSERT INTO queue VALUES('refused')")
                    self.conn.rollback()
                (self.root / "config.json").write_bytes(original_config)
                (self.root / "sentinel/coordinator.py").write_bytes(original_source)
                self.server_backend.status = IdentityStatus.ALIVE

    def test_native_mutex_held_refuses_new_rpc(self):
        key = threading.current_thread(), "fixture-original-native-mutex"
        with windows._THREAD_NAMES_LOCK:
            windows._THREAD_NAMES.add(key)
        try:
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "lock_held"):
                with generation.readiness_scope(self.db):
                    self.fail("lock-held acquisition was accepted")
        finally:
            with windows._THREAD_NAMES_LOCK:
                windows._THREAD_NAMES.discard(key)
        self.assertEqual(self.events, [])

    def test_original_duplicate_is_taken_inside_peer_scope_before_cleanup(self):
        with generation.readiness_scope(self.db) as scope:
            self.assertIs(type(scope.authority), transport.DailyReadinessAuthority)
            self.assertNotEqual(scope.authority._peer._handle, self.connections[0].retained._handle)
            self.assertTrue(self.connections[0].closed)
            self.assertLess(self.events.index("peer.duplicate"), self.events.index("pipe.peer.close"))
            self.assertLess(self.events.index("pipe.close"), self.events.index("caller.close", self.events.index("pipe.close")))

    def test_authority_cannot_be_used_by_another_thread(self):
        failures = []
        with generation.readiness_scope(self.db) as scope:
            def check():
                try:
                    scope.authority.revalidate(scope.authority._endpoint, scope.authority._binding)
                except BaseException as error:
                    failures.append(error)
            worker = threading.Thread(target=check)
            worker.start()
            worker.join()
            self.assertEqual(len(failures), 1)
            self.assertIn("authority_unavailable", str(failures[0]))

    def test_unknown_pipe_cleanup_retains_failed_original_acquisition(self):
        self.pipe_cleanup_error = RuntimeError("fixture pipe close unknown")
        with self.assertRaises(transport.DailyReadinessError) as caught:
            with generation.readiness_scope(self.db):
                self.fail("pipe cleanup unverified")
        self.assertIsNotNone(caught.exception._daily_readiness_connection)
        self.assertTrue(caught.exception._daily_readiness_cleanup_pending)
        self.assertIsNotNone(caught.exception.daily_readiness_scope.error)

    def test_unknown_duplicate_output_keeps_native_owner_and_prevents_replacement(self):
        failure = RuntimeError("fixture duplicate interrupted")
        self.server_backend.duplicate_error = failure
        with self.assertRaises(transport.DailyReadinessError) as caught:
            with generation.readiness_scope(self.db):
                self.fail("uncertain duplicate accepted")
        self.assertTrue(failure._identity_handle_cleanup)
        self.assertIs(caught.exception.daily_readiness_scope.error, caught.exception)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending"):
            with generation.readiness_scope(self.db):
                self.fail("unknown duplicate replaced")

    def test_bad_authenticated_reply_does_not_issue_retained_authority(self):
        self.reply_changes["endpoint_id"] = str(uuid4())
        with self.assertRaisesRegex(transport.DailyReadinessError, "reply_mismatch"):
            with generation.readiness_scope(self.db):
                self.fail("wrong reply accepted")
        self.assertNotIn("peer.duplicate", self.events)
        self.assertTrue(self.connections[0].closed)

    def test_changed_ledger_identity_fails_at_write(self):
        original = generation._ledger_identity(self.db)
        with generation.readiness_scope(self.db):
            self.bind(self.conn)
            with patch.object(generation, "_ledger_identity", return_value=(original[0], original[1] + 1)):
                with self.assertRaises(sqlite3.OperationalError):
                    self.conn.execute("INSERT INTO queue VALUES('wrong-ledger')")
                self.conn.rollback()

    def test_cross_ledger_nested_scope_refuses_without_another_rpc(self):
        with generation.readiness_scope(self.db):
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "ledger_changed"):
                with generation.readiness_scope(self.db.with_name("other.db")):
                    self.fail("cross-ledger authority")
        self.assertEqual(self.events.count("rpc"), 1)

    def test_caller_close_unknown_retains_original_authority_and_blocks_reacquisition(self):
        self.caller_backend.close_error = RuntimeError("fixture close unknown")
        with self.assertRaisesRegex(RuntimeError, "fixture close unknown") as caught:
            with generation.readiness_scope(self.db):
                self.fail("caller cleanup unverified")
        error = caught.exception
        self.assertIsNotNone(error._daily_readiness_authority)
        self.assertIsNotNone(error.daily_readiness_current_process)
        self.caller_backend.close_error = None
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending"):
            with generation.readiness_scope(self.db):
                self.fail("uncertain original cleanup was replaced")

    def test_retained_close_unknown_is_not_retried(self):
        with self.assertRaisesRegex(RuntimeError, "retained close unknown") as caught:
            with generation.readiness_scope(self.db) as scope:
                self.server_backend.close_error = RuntimeError("retained close unknown")
        before = len(self.events)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending"):
            scope.close()
        self.assertEqual(len(self.events), before)
        self.assertIs(caught.exception.daily_readiness_scope, scope)

    def test_nested_cleanup_failure_retains_authority_and_primary(self):
        failure = RuntimeError("fixture nested SQL close unknown")
        failure.add_note("lifecycle_connection_cleanup_failed")
        with self.assertRaises(RuntimeError) as caught:
            with generation.readiness_scope(self.db) as scope:
                raise failure
        self.assertIs(caught.exception, failure)
        self.assertIs(scope.error, failure)
        self.assertFalse(scope.authority._closed)

    def test_caught_nested_cleanup_failure_does_not_become_success(self):
        failure = RuntimeError("fixture caught SQL close unknown")
        failure.add_note("lifecycle_connection_cleanup_failed")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending") as caught:
            with generation.readiness_scope(self.db) as outer:
                try:
                    with generation.readiness_scope(self.db):
                        raise failure
                except RuntimeError:
                    pass  # The host may log it, but original custody stays.
        self.assertIs(caught.exception.daily_readiness_scope, outer)
        self.assertIs(outer.error, failure)
        self.assertFalse(outer.authority._closed)

    def test_remote_cleanup_never_has_capacity_or_out_of_scope_nonce_authority(self):
        policy = self.store._policy
        guard = policy.prepare(self.identity.logon_id)
        with generation.readiness_scope(self.db):
            with generation.readiness_nonce_cleanup(policy, guard):
                policy._held.cleanup_guard = guard
                try:
                    self.bind(self.conn)
                    for sql in ("PRAGMA journal_mode=OFF", "PRAGMA writable_schema=ON",
                                "PRAGMA foreign_keys=OFF", "PRAGMA busy_timeout=10000"):
                        with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                            self.conn.execute(sql)
                    with self.assertRaises(sqlite3.DatabaseError):
                        self.conn.execute("INSERT INTO queue VALUES('forbidden')")
                    self.conn.rollback()
                finally:
                    policy._held.cleanup_guard = None
            with self.assertRaises(sqlite3.DatabaseError):
                self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
            self.conn.rollback()

    def test_preacquired_two_ledger_scope_preserves_policy_order_without_inner_rpc(self):
        isolated = self.isolated_store()
        observed = []
        original_read = generation._ReadinessScope.read
        def read(owner):
            self.assertFalse(self.provider.active)
            self.assertFalse(isolated._policy.provider.active)
            observed.append(owner.path)
            return original_read(owner)
        with patch.object(generation._ReadinessScope, "read", read):
            with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
                guard = self.store._policy.prepare(self.identity.logon_id)
                with self.store._policy.hold(guard):
                    with generation.readiness_scope(isolated.db_path):
                        nested = isolated._policy.prepare(self.identity.logon_id)
                        with isolated._policy.hold(nested):
                            with self.store._transaction() as conn:
                                conn.execute("INSERT INTO queue VALUES('under-two-locks')")
                            with isolated._transaction() as conn:
                                self.assertIsNone(generation.read_generation(conn))
                                with self.assertRaises(sqlite3.OperationalError):
                                    conn.execute("SELECT sentinel_daily_generation()")
        self.assertEqual(observed, [self.db.resolve(), isolated.db_path.resolve()])
        self.assertEqual(self.events.count("rpc"), 1)

    def test_group_isolated_absence_cannot_become_a_daily_generation(self):
        isolated = self.isolated_store()
        with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
            with closing(sqlite3.connect(isolated.db_path, isolation_level=None)) as conn:
                conn.execute("ATTACH DATABASE ? AS fixture_daily", (str(self.db),))
                conn.execute("CREATE TABLE adaptive_daily_generation AS SELECT * FROM fixture_daily.adaptive_daily_generation")
            with self.assertRaises(generation.DailyGenerationUnavailable):
                with isolated._connection():
                    self.fail("new generation accepted from originally absent scope")
        self.assertEqual(self.events.count("rpc"), 1)

    def test_isolated_file_identity_replacement_rejects_on_consumer_connection(self):
        isolated = self.isolated_store()
        identity = generation._ledger_identity(isolated.db_path)
        original_identity = generation._ledger_identity
        with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
            def changed(path):
                return ((identity[0], identity[1] + 1) if Path(path) == isolated.db_path
                        else original_identity(path))
            with patch.object(generation, "_ledger_identity", side_effect=changed), \
                    self.assertRaisesRegex(generation.DailyGenerationUnavailable, "identity_changed"):
                with isolated._connection():
                    self.fail("replacement isolated file accepted")

    def test_isolated_transaction_revalidates_absence_after_begin(self):
        isolated = self.isolated_store()
        with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
            with isolated._connection() as conn:
                conn.execute("ATTACH DATABASE ? AS fixture_daily", (str(self.db),))
                conn.execute("CREATE TABLE adaptive_daily_generation AS SELECT * FROM fixture_daily.adaptive_daily_generation")
                conn.execute("BEGIN IMMEDIATE")
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "absence_required"):
                    generation.revalidate_transaction(conn, db_path=isolated.db_path)
                conn.rollback()

    def test_group_selectors_do_not_borrow_other_ledger_cleanup_marker(self):
        isolated = self.isolated_store()
        guard = self.store._policy.prepare(self.identity.logon_id)
        with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
            with generation.readiness_scope(self.db) as daily:
                with generation.readiness_nonce_cleanup(self.store._policy, guard):
                    with generation.readiness_scope(isolated.db_path) as other:
                        self.assertIsNone(other.cleanup)
                        self.assertIsNone(other.authority)
                    self.assertIs(generation._READINESS_LOCAL.scope, daily)
                    self.assertIs(daily.cleanup[1], guard)

    def test_native_only_isolated_group_never_reads_daily_or_acquires_rpc(self):
        isolated = self.isolated_store()
        with patch.object(generation, "_prove_retained_owner_ready",
                          side_effect=AssertionError("native-only restore must not request daily readiness")):
            with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
                guard = isolated._policy.prepare(self.identity.logon_id)
                with isolated._policy.hold(guard):
                    with isolated._transaction() as conn:
                        self.assertIsNone(generation.read_generation(conn))
        self.assertEqual(self.events.count("rpc"), 0)

    def fill_pending_pool(self, *, absence_only):
        pool = generation._ABSENCE_SCOPES if absence_only else generation._READINESS_SCOPES
        limit = generation.MAX_ABSENCE_SCOPES if absence_only else generation.MAX_READINESS_SCOPES
        # These are explicit original pending-observation fixtures; they never
        # manufacture an authenticated authority or touch a native resource.
        with generation._READINESS_SCOPES_LOCK:
            for index in range(limit):
                owner = generation._ReadinessScope(
                    self.root.resolve() / f"pending-{absence_only}-{index}.sqlite3",
                    absence_only=absence_only)
                pool[id(owner)] = owner

    def test_absence_only_native_restore_is_independent_of_full_daily_pool(self):
        isolated = self.isolated_store()
        self.fill_pending_pool(absence_only=False)
        with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
            guard = isolated._policy.prepare(self.identity.logon_id)
            with isolated._policy.hold(guard):
                with isolated._transaction() as conn:
                    self.assertIsNone(generation.read_generation(conn))
        self.assertEqual(self.events.count("rpc"), 0)
        self.assertEqual(len(generation._READINESS_SCOPES), generation.MAX_READINESS_SCOPES)
        self.assertEqual(generation._ABSENCE_SCOPES, {})

    def test_absence_pool_has_its_own_pending_observation_bound(self):
        isolated = self.isolated_store()
        self.fill_pending_pool(absence_only=True)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scopes_pending"):
            with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
                self.fail("full absence pool accepted another original")
        self.assertEqual(self.events.count("rpc"), 0)

    def test_declared_absence_rejects_existing_local_generation_without_rpc(self):
        with patch.dict(generation._LOCAL_GENERATIONS, {self.owner.generation: self.owner}):
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "absence_required"):
                with generation.readiness_scopes((self.db,), absent_paths=(self.db,)):
                    self.fail("absence declaration acquired local generation authority")
        self.assertEqual(self.events.count("rpc"), 0)

    def test_absence_declaration_must_select_an_original_group_path(self):
        isolated = self.isolated_store()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "group_invalid"):
            with generation.readiness_scopes((isolated.db_path,), absent_paths=(self.db,)):
                self.fail("unprepared absence path accepted")
        self.assertEqual(self.events.count("rpc"), 0)

    def test_second_scope_unknown_reader_cleanup_retains_both_originals(self):
        isolated = self.isolated_store()
        original_close = generation._ReadinessReader.close
        def close(reader):
            filename = reader.connection.execute("PRAGMA database_list").fetchone()[2]
            if Path(filename) == isolated.db_path:
                reader.close_unknown = True
                raise RuntimeError("fixture isolated close unknown")
            return original_close(reader)
        with patch.object(generation._ReadinessReader, "close", close), \
                self.assertRaises(RuntimeError) as caught:
            with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
                self.fail("second acquisition cleanup unverified")
        originals = caught.exception._daily_readiness_scopes
        self.assertEqual({owner.path for owner in originals}, {self.db.resolve(), isolated.db_path})
        daily = next(owner for owner in originals if owner.path == self.db.resolve())
        self.assertFalse(daily.authority._closed)

    def test_group_refuses_third_ledger_and_more_than_two_preparations(self):
        isolated = self.isolated_store()
        third = self.root / "third.sqlite3"
        with generation.readiness_scopes((self.db, isolated.db_path), absent_paths=(isolated.db_path,)):
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "ledger_changed"):
                with generation.readiness_scope(third):
                    self.fail("unprepared ledger selected")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "group_invalid"):
            with generation.readiness_scopes((self.db, isolated.db_path, third)):
                self.fail("third preparation accepted")

    def test_pending_unobserved_scopes_count_toward_atomic_custody_bound(self):
        release, all_entered = threading.Event(), threading.Event()
        lock = threading.Lock()
        arrived, failures = [], []
        def blocked_read(scope):
            with lock:
                arrived.append(scope)
                if len(arrived) == generation.MAX_READINESS_SCOPES:
                    all_entered.set()
            if not release.wait(5):
                raise AssertionError("fixture release timeout")
        def acquire():
            try:
                with generation.readiness_scope(self.db):
                    pass
            except BaseException as error:
                failures.append(error)
        with patch.object(generation._ReadinessScope, "read", blocked_read):
            workers = [threading.Thread(target=acquire) for _ in range(generation.MAX_READINESS_SCOPES)]
            try:
                for worker in workers:
                    worker.start()
                self.assertTrue(all_entered.wait(5))
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scopes_pending"):
                    with generation.readiness_scope(self.db):
                        self.fail("unobserved pending owners did not count")
            finally:
                release.set()
                for worker in workers:
                    worker.join()
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
