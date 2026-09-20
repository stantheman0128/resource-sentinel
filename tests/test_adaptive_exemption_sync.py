"""Portable exemption transactions with real SQLite and explicit fake POLICY.

These tests never query processes, create native objects or open daily data.
They establish cooperating-writer semantics, not a Windows control capability.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import FrozenInstanceError
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import exemption_sync as sync
from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleStore
from tests.fixtures.adaptive_evidence import FixturePolicyProvider


NOW = 2_000_000_000.0
LOGON = "S-1-5-5-1-2"


class ExemptionSynchronizationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        self.exemptions = SimpleNamespace(path=self.directory / "exemptions.sqlite3")
        self.provider = FixturePolicyProvider(LOGON)
        self.store = LifecycleStore(self.db, local_host_id="fixture-host", policy_provider=self.provider)
        # Actual historical SQL, without importing the changing public helper.
        with closing(sqlite3.connect(self.exemptions.path)) as conn:
            conn.execute("""CREATE TABLE exemptions (
                id TEXT PRIMARY KEY, root_pid INTEGER NOT NULL, root_started REAL NOT NULL,
                created_at REAL NOT NULL, expires_at REAL NOT NULL, reason TEXT NOT NULL,
                revoked_at REAL, owner_metadata TEXT NOT NULL DEFAULT '{}')""")
            conn.commit()

    def connection(self, path=None):
        conn = sqlite3.connect(path or self.exemptions.path, timeout=0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    @staticmethod
    def record(pid=501, *, started=123.5, expires=None):
        return dict(id=uuid4().hex, root_pid=pid, root_started=started,
                    created_at=NOW, expires_at=NOW + 3600 if expires is None else expires,
                    reason="explicit fixture authorization", revoked_at=None,
                    owner_metadata='{"session_name":"fixture"}')

    @contextmanager
    def held(self, store=None):
        store = self.store if store is None else store
        guard = store._policy.prepare(LOGON)
        with store._policy.hold(guard):
            yield guard

    def bind(self):
        with self.held():
            return sync.bind_policy_locked(self.exemptions, self.store)

    def snapshot(self, *, now=NOW):
        with self.held():
            return sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=now)

    def rows(self):
        return [dict(row) for row in self.connection().execute("SELECT * FROM exemptions ORDER BY id")]

    def runtime(self):
        return dict(self.connection(self.db).execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def assert_writer_unlocked(self, path):
        with closing(sqlite3.connect(path, timeout=0, isolation_level=None)) as probe:
            probe.execute("BEGIN IMMEDIATE")
            probe.rollback()

    def factory(self, path):
        self.assertEqual(Path(path).resolve(), self.db.resolve())
        self.assert_writer_unlocked(self.db)
        self.assert_writer_unlocked(self.exemptions.path)
        return self.store

    def test_unbound_grant_preserves_record_and_original_deadline_on_retry(self):
        original = self.record()
        first = sync.grant_record(self.exemptions, original, now=NOW)
        self.assertEqual((first["id"], first["expires_at"]), (original["id"], original["expires_at"]))
        self.assertEqual((first["grant_state"], first["enforcement_state"]), ("active", "not_applicable"))
        retry = self.record(started=original["root_started"] + .005, expires=NOW + 7200)
        second = sync.grant_record(self.exemptions, retry, now=NOW + 1)
        self.assertEqual((second["id"], second["expires_at"], second["exemption_revision"]),
                         (first["id"], first["expires_at"], first["exemption_revision"]))
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.rows()[0]["reason"], original["reason"])

    def test_three_unexpired_slots_are_atomic_and_expiry_does_not_revoke(self):
        records = [self.record(501 + index, expires=NOW + 60) for index in range(3)]
        for row in records:
            sync.grant_record(self.exemptions, row, now=NOW)
        before = self.rows()
        with self.assertRaisesRegex(ValueError, "exemption_limit_reached"):
            sync.grant_record(self.exemptions, self.record(600), now=NOW + 59)
        self.assertEqual(self.rows(), before)
        fourth = sync.grant_record(self.exemptions, self.record(600), now=NOW + 60)
        self.assertEqual(fourth["root_pid"], 600)
        self.assertEqual(len(self.rows()), 4)
        self.assertTrue(all(row["revoked_at"] is None for row in self.rows()))

    def test_revoke_increments_once_and_missing_or_repeated_revoke_is_noop(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        before = self.snapshot()
        with self.held():
            first = sync.commit_revoke_locked(self.exemptions, row["id"], lifecycle_store=self.store, now=NOW + 1)
            again = sync.commit_revoke_locked(self.exemptions, row["id"], lifecycle_store=self.store, now=NOW + 2)
            absent = sync.commit_revoke_locked(self.exemptions, uuid4().hex, lifecycle_store=self.store, now=NOW + 3)
        self.assertEqual(first, {"revoked": 1, "exemption_revision": before.revision + 1})
        self.assertEqual(again, {"revoked": 0, "exemption_revision": first["exemption_revision"]})
        self.assertEqual(absent, again)
        self.assertEqual(self.rows()[0]["revoked_at"], NOW + 1)

    def test_binding_and_locked_apis_require_current_policy_ownership(self):
        for operation in (
                lambda: sync.bind_policy_locked(self.exemptions, self.store),
                lambda: sync.commit_grant_locked(self.exemptions, self.record(), lifecycle_store=self.store, now=NOW),
                lambda: sync.commit_revoke_locked(self.exemptions, uuid4().hex, lifecycle_store=self.store, now=NOW),
                lambda: sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)):
            with self.subTest(operation=operation), self.assertRaises((PolicyError, sync.ExemptionSyncError)):
                operation()
        self.assertEqual(self.rows(), [])

    def test_binding_is_immutable_and_rejects_another_policy_instance(self):
        binding = self.bind()
        before = self.snapshot()
        with self.held() as guard:
            again = sync.bind_policy_locked(self.exemptions, self.store)
            self.assertEqual((binding.instance_id, binding.logon_id),
                             (guard.binding.instance_id, guard.binding.logon_id))
            self.assertEqual(again, binding)
        # Explicit corruption/replacement fixture: the same ledger now names a
        # different POLICY instance. A pathname check alone cannot reject it.
        runtime = self.connection(self.db)
        runtime.execute("UPDATE adaptive_runtime SET policy_instance_id=? WHERE singleton=1", (str(uuid4()),))
        with self.held():
            with self.assertRaises(sync.ExemptionSyncError):
                sync.bind_policy_locked(self.exemptions, self.store)
            with self.assertRaises(sync.ExemptionSyncError):
                sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)
        runtime.execute("UPDATE adaptive_runtime SET policy_instance_id=? WHERE singleton=1", (binding.instance_id,))
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            binding.instance_id = uuid4().hex

    def test_matching_persistent_binding_does_not_authorize_another_thread_or_store(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        other_store = LifecycleStore(self.db, local_host_id="fixture-host",
                                     policy_provider=FixturePolicyProvider(LOGON))
        before = self.rows()
        metadata = dict(self.connection().execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone())

        def operations(store):
            return (
                lambda: sync.bind_policy_locked(self.exemptions, store),
                lambda: sync.commit_grant_locked(self.exemptions, self.record(700), lifecycle_store=store, now=NOW),
                lambda: sync.commit_revoke_locked(self.exemptions, row["id"], lifecycle_store=store, now=NOW + 1),
                lambda: sync.snapshot_locked(self.exemptions, lifecycle_store=store, now=NOW),
            )

        with self.held(), ThreadPoolExecutor(max_workers=1) as executor:
            for operation in operations(self.store):
                with self.subTest(owner="other-thread"), self.assertRaises((PolicyError, sync.ExemptionSyncError)):
                    executor.submit(operation).result(timeout=3)
            for operation in operations(other_store):
                with self.subTest(owner="other-store"), self.assertRaises((PolicyError, sync.ExemptionSyncError)):
                    operation()
        self.assertEqual(self.rows(), before)
        self.assertEqual(dict(self.connection().execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone()), metadata)

    def test_bound_old_insert_update_delete_sql_is_rejected(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        before = self.rows()
        old = self.connection()
        operations = (
            ("INSERT INTO exemptions(id,root_pid,root_started,created_at,expires_at,reason,revoked_at) VALUES(?,?,?,?,?,?,NULL)",
             (uuid4().hex, 777, 10.0, NOW, NOW + 3600, "old writer")),
            ("UPDATE exemptions SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (NOW + 1, row["id"])),
            ("DELETE FROM exemptions WHERE id=?", (row["id"],)),
        )
        for sql, parameters in operations:
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                old.execute(sql, parameters)
            self.assertEqual(self.rows(), before)

    def test_bound_metadata_cannot_reset_and_missing_metadata_cannot_reopen_unbound(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        conn = self.connection()
        metadata = dict(conn.execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone())
        leases = self.rows()
        writes = (
            ("UPDATE exemption_sync SET coordination_required=0,policy_instance_id=NULL,policy_logon_id=NULL WHERE singleton=1", ()),
            ("DELETE FROM exemption_sync WHERE singleton=1", ()),
            ("INSERT OR REPLACE INTO exemption_sync(singleton,schema_version,revision,coordination_required,policy_instance_id,policy_logon_id,store_id) VALUES(1,1,?,0,NULL,NULL,?)",
             (metadata["revision"], metadata["store_id"])),
        )
        for sql, parameters in writes:
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "exemption_binding_immutable"):
                conn.execute(sql, parameters)
            self.assertEqual(dict(conn.execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone()), metadata)
            self.assertEqual(self.rows(), leases)
        # Explicit isolated schema-corruption fixture, never a supported API.
        # Remaining protocol artifacts must prohibit a fresh unbound bootstrap.
        conn.execute("DROP TABLE exemption_sync")
        callbacks = []
        with self.assertRaisesRegex(sync.ExemptionSyncError, "exemption_sync_missing"):
            sync.grant_record(self.exemptions, self.record(777), now=NOW,
                              policy_factory=self.factory, after_unlock=callbacks.append)
        self.assertEqual(self.rows(), leases)
        self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='exemption_sync'").fetchone())
        self.assertEqual(callbacks, [])

    def assert_replaced_exemption_database_fails_closed(self, replacement):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        # Only this TemporaryDirectory's file is removed, and no exemption
        # connection is retained across unlink on Windows.
        self.exemptions.path.unlink()
        if replacement != "missing":
            with closing(sqlite3.connect(self.exemptions.path)) as conn:
                if replacement == "legacy":
                    conn.execute("""CREATE TABLE exemptions (
                        id TEXT PRIMARY KEY, root_pid INTEGER NOT NULL, root_started REAL NOT NULL,
                        created_at REAL NOT NULL, expires_at REAL NOT NULL, reason TEXT NOT NULL,
                        revoked_at REAL)""")
                conn.commit()
        original_bytes = self.exemptions.path.read_bytes() if self.exemptions.path.exists() else None
        callbacks = []
        with self.assertRaises(sync.ExemptionSyncError):
            sync.grant_record(self.exemptions, self.record(777), now=NOW,
                              policy_factory=lambda path: self.store, after_unlock=callbacks.append)
        with self.assertRaises(sync.ExemptionSyncError):
            sync.revoke_record(self.exemptions, row["id"], now=NOW + 1,
                               policy_factory=lambda path: self.store, after_unlock=callbacks.append)
        with self.held():
            with self.assertRaises(sync.ExemptionSyncError):
                sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)
            with self.assertRaises(sync.ExemptionSyncError):
                sync.bind_policy_locked(self.exemptions, self.store)
        self.assertEqual(callbacks, [])
        if replacement == "missing":
            self.assertFalse(self.exemptions.path.exists())
        else:
            self.assertEqual(self.exemptions.path.read_bytes(), original_bytes)
            with closing(sqlite3.connect(self.exemptions.path)) as conn:
                tables = {record[0] for record in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                self.assertEqual(tables, {"exemptions"} if replacement == "legacy" else set())
                if replacement == "legacy":
                    self.assertEqual(conn.execute("SELECT count(*) FROM exemptions").fetchone()[0], 0)

    def test_sticky_binding_survives_missing_exemption_database(self):
        self.assert_replaced_exemption_database_fails_closed("missing")

    def test_sticky_binding_rejects_empty_replacement_database(self):
        self.assert_replaced_exemption_database_fails_closed("empty")

    def test_sticky_binding_rejects_historical_unbound_replacement_database(self):
        self.assert_replaced_exemption_database_fails_closed("legacy")

    def test_interrupted_bind_keeps_sticky_intent_until_explicit_locked_retry(self):
        original = self.record()
        sync.grant_record(self.exemptions, original, now=NOW)
        before = self.rows()
        with self.held() as guard:
            with patch.object(sync, "_commit_binding", side_effect=RuntimeError("fixture_bind_interrupted")):
                with self.assertRaisesRegex(RuntimeError, "fixture_bind_interrupted"):
                    sync.bind_policy_locked(self.exemptions, self.store)
            with closing(sqlite3.connect(self.db)) as conn:
                conn.row_factory = sqlite3.Row
                intents = [dict(row) for row in conn.execute("SELECT * FROM adaptive_exemption_binding")]
            self.assertEqual(len(intents), 1)
            self.assertIn(guard.binding.instance_id, intents[0].values())
            self.assertIn(guard.binding.logon_id, intents[0].values())
            with closing(sqlite3.connect(self.exemptions.path)) as conn:
                store_id = conn.execute("SELECT store_id FROM exemption_sync WHERE singleton=1").fetchone()[0]
            self.assertEqual(intents[0]["store_id"], store_id)
        self.assertEqual(self.rows(), before)
        with self.assertRaises(sync.ExemptionSyncError):
            sync.grant_record(self.exemptions, self.record(888), now=NOW,
                              policy_factory=lambda path: self.store)
        with self.assertRaises(sync.ExemptionSyncError):
            sync.revoke_record(self.exemptions, original["id"], now=NOW + 1,
                               policy_factory=lambda path: self.store)
        with self.held():
            with self.assertRaises(sync.ExemptionSyncError):
                sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)
            binding = sync.bind_policy_locked(self.exemptions, self.store)
            repaired = sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)
        self.assertEqual(repaired.binding, binding)
        self.assertEqual([row["id"] for row in repaired.leases], [original["id"]])
        added = sync.grant_record(self.exemptions, self.record(888), now=NOW,
                                 policy_factory=self.factory)
        self.assertEqual((added["grant_state"], added["enforcement_state"]), ("recorded", "restore_pending"))

    def test_preopened_legacy_connection_and_cached_sql_are_fenced_after_binding(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        old = self.connection()
        sql = "UPDATE exemptions SET reason=? WHERE id=?"
        old.execute(sql, ("permitted before binding", row["id"]))
        self.bind()
        before = self.rows()
        with self.assertRaises(sqlite3.DatabaseError):
            old.execute(sql, ("must fail after binding", row["id"]))
        self.assertEqual(self.rows(), before)

    def test_unbound_actual_legacy_semantic_writes_increment_revision_but_noop_does_not(self):
        row = self.record()
        granted = sync.grant_record(self.exemptions, row, now=NOW)
        conn = self.connection()

        def revision():
            return conn.execute("SELECT revision FROM exemption_sync WHERE singleton=1").fetchone()[0]

        self.assertEqual(revision(), granted["exemption_revision"])
        conn.execute("UPDATE exemptions SET reason=? WHERE id=?", ("legacy semantic change", row["id"]))
        self.assertEqual(revision(), granted["exemption_revision"] + 1)
        conn.execute("UPDATE exemptions SET reason=? WHERE id=?", ("legacy semantic change", row["id"]))
        self.assertEqual(revision(), granted["exemption_revision"] + 1)
        conn.execute("DELETE FROM exemptions WHERE id=?", (row["id"],))
        self.assertEqual(revision(), granted["exemption_revision"] + 2)
        conn.execute("DELETE FROM exemptions WHERE id=?", (row["id"],))
        self.assertEqual(revision(), granted["exemption_revision"] + 2)

    def test_snapshot_preserves_raw_unknown_roots_and_filters_only_lease_time_and_revocation(self):
        active = self.record(4_000_000_000)
        expired = self.record(502, expires=NOW + 60)
        revoked = self.record(503)
        for row in (active, expired, revoked):
            sync.grant_record(self.exemptions, row, now=NOW)
        sync.revoke_record(self.exemptions, revoked["id"], now=NOW + .5)
        self.bind()
        result = self.snapshot(now=NOW + 60)
        self.assertIsInstance(result.leases, tuple)
        self.assertEqual([row["id"] for row in result.leases], [active["id"]])
        self.assertEqual(result.leases[0]["root_started"], active["root_started"])
        self.assertNotIn("root_created_filetime_100ns", result.leases[0])
        with self.assertRaises(TypeError):
            result.leases[0]["reason"] = "mutated snapshot"

    def test_snapshot_rejects_malformed_active_lease_instead_of_reporting_no_exemption(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        conn = self.connection()
        # Explicit corrupt-ledger fixture; this is not an alternate authority.
        # Protocol-aware SQL keeps the installed fences enabled throughout.
        for field, invalid in (("root_pid", 0), ("root_started", "unknown"),
                               ("created_at", "unknown"), ("expires_at", "unknown"),
                               ("owner_metadata", "not-json")):
            with self.subTest(field=field):
                conn.execute(f"UPDATE exemptions SET {field}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                             (invalid, row["id"]))
                with self.held():
                    with self.assertRaises(sync.ExemptionSyncError):
                        sync.snapshot_locked(self.exemptions, lifecycle_store=self.store, now=NOW)
                conn.execute(f"UPDATE exemptions SET {field}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                             (row[field], row["id"]))
        self.assertEqual([lease["id"] for lease in self.snapshot().leases], [row["id"]])

    def test_malformed_revocation_is_unknown_authority_and_cannot_free_a_slot(self):
        for index, invalid in enumerate(("unknown", -1.0, float("inf"))):
            with self.subTest(revoked_at=invalid):
                directory = self.directory / ("invalid-revocation-" + str(index))
                directory.mkdir()
                exemptions = SimpleNamespace(path=directory / "exemptions.sqlite3")
                store = LifecycleStore(directory / "sentinel.db", local_host_id="fixture-host",
                                       policy_provider=FixturePolicyProvider(LOGON))
                records = [self.record(1100 + item) for item in range(3)]
                for row in records:
                    sync.grant_record(exemptions, row, now=NOW)
                with self.held(store):
                    sync.bind_policy_locked(exemptions, store)
                with closing(sqlite3.connect(exemptions.path, isolation_level=None)) as conn:
                    conn.execute("UPDATE exemptions SET revoked_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                 (invalid, records[0]["id"]))
                    with self.held(store):
                        with self.assertRaisesRegex(sync.ExemptionSyncError, "exemption_snapshot_invalid"):
                            sync.snapshot_locked(exemptions, lifecycle_store=store, now=NOW + 1)
                    contender = self.record(1200)
                    with self.assertRaisesRegex(sync.ExemptionSyncError, "exemption_snapshot_invalid"):
                        sync.grant_record(exemptions, contender, now=NOW + 1, policy_factory=lambda path: store)
                    self.assertEqual(conn.execute("SELECT count(*) FROM exemptions").fetchone()[0], 3)
                    self.assertIsNone(conn.execute("SELECT 1 FROM exemptions WHERE id=?", (contender["id"],)).fetchone())

    def test_finite_revocation_removes_only_that_lease_and_permits_the_next_grant(self):
        records = [self.record(1300 + item) for item in range(3)]
        for row in records:
            sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        self.assertEqual(sync.revoke_record(self.exemptions, records[0]["id"], now=NOW + 1,
                                           policy_factory=self.factory), 1)
        self.assertEqual({row["id"] for row in self.snapshot(now=NOW + 1).leases},
                         {row["id"] for row in records[1:]})
        admitted = sync.grant_record(self.exemptions, self.record(1400), now=NOW + 1,
                                     policy_factory=self.factory)
        self.assertEqual(len(self.snapshot(now=NOW + 1).leases), 3)
        self.assertIn(admitted["id"], {row["id"] for row in self.snapshot(now=NOW + 1).leases})

    def test_bound_facade_uses_policy_and_calls_recovery_only_after_full_unlock(self):
        self.bind()
        callbacks = []

        def after_unlock(*args, **kwargs):
            self.assertFalse(self.provider.active)
            self.assertIsNone(self.store._policy.current_guard())
            self.assertIsNone(self.runtime()["policy_entry_nonce"])
            self.assert_writer_unlocked(self.db)
            self.assert_writer_unlocked(self.exemptions.path)
            callbacks.append((args, kwargs))

        row = self.record()
        granted = sync.grant_record(self.exemptions, row, now=NOW,
                                    policy_factory=self.factory, after_unlock=after_unlock)
        self.assertEqual((granted["grant_state"], granted["enforcement_state"]), ("recorded", "restore_pending"))
        self.assertEqual(len(callbacks), 1)
        revoked = sync.revoke_record(self.exemptions, row["id"], now=NOW + 1,
                                     policy_factory=self.factory, after_unlock=after_unlock)
        self.assertEqual(revoked, 1)
        self.assertEqual(len(callbacks), 2)

    def test_existing_pending_policy_nonce_prevents_new_bound_grant(self):
        self.bind()
        pending = self.store._policy.prepare(LOGON)
        callbacks = []
        with self.assertRaises((PolicyError, sync.ExemptionSyncError)):
            sync.grant_record(self.exemptions, self.record(), now=NOW,
                              policy_factory=self.factory, after_unlock=lambda *args: callbacks.append(args))
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.runtime()["policy_entry_nonce"], pending.nonce)
        self.assertEqual(callbacks, [])

    def test_bound_fourth_grant_clean_rejection_releases_policy_and_keeps_revocation_available(self):
        grants = [self.record(900 + index) for index in range(3)]
        for row in grants:
            sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        before = self.rows()
        revision = self.snapshot().revision
        callbacks = []
        with self.assertRaisesRegex(sync.ExemptionSyncError, "exemption_limit_reached"):
            sync.grant_record(self.exemptions, self.record(999), now=NOW,
                              policy_factory=self.factory, after_unlock=callbacks.append)
        self.assertEqual(self.rows(), before)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.store._policy.current_guard())
        self.assertFalse(self.provider.active)
        self.assertEqual(callbacks, [])
        self.assertEqual(self.snapshot().revision, revision)
        self.assertEqual(sync.revoke_record(self.exemptions, grants[0]["id"], now=NOW + 1,
                                           policy_factory=self.factory), 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(sum(row["revoked_at"] is not None for row in self.rows()), 1)

    def test_existing_policy_store_does_not_create_a_missing_database(self):
        missing = self.directory / "missing-sentinel.db"
        with self.assertRaises((sync.ExemptionSyncError, sqlite3.Error, FileNotFoundError)):
            existing = sync.ExistingPolicyStore(missing, policy_provider=FixturePolicyProvider(LOGON))
            with existing._connection() as conn:
                conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
        self.assertFalse(missing.exists())

    def test_existing_policy_adapter_can_coordinate_without_running_lifecycle_migrations(self):
        binding = self.bind()
        with patch("sentinel.adaptive.store.migrate_schema", side_effect=AssertionError("unexpected lifecycle migration")):
            existing = sync.ExistingPolicyStore(self.db, expected_binding=binding, policy_provider=self.provider)
            result = sync.grant_record(self.exemptions, self.record(), now=NOW, policy_factory=lambda path: existing)
        self.assertEqual((result["grant_state"], result["enforcement_state"]), ("recorded", "restore_pending"))
        self.assertIsNone(existing._policy.current_guard())
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_four_concurrent_unbound_grants_cannot_commit_a_fourth_slot(self):
        records = [self.record(800 + index) for index in range(4)]

        def grant(record):
            try:
                return sync.grant_record(self.exemptions, record, now=NOW)
            except ValueError as error:
                self.assertIn("exemption_limit_reached", str(error))
                return None

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(grant, records))
        self.assertEqual(sum(result is not None for result in results), 3)
        self.assertEqual(len(self.rows()), 3)

    def test_abort_during_exemption_bind_preserves_sticky_intent_until_original_store_retry(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        conn = self.connection()
        before = dict(conn.execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone())
        leases = self.rows()
        conn.execute("""CREATE TRIGGER fixture_reject_binding BEFORE UPDATE ON exemption_sync
            WHEN OLD.coordination_required=0 AND NEW.coordination_required=1
            BEGIN SELECT RAISE(ABORT,'fixture_binding_failure'); END""")
        with self.held() as guard:
            with self.assertRaisesRegex(sync.ExemptionSyncError, "exemption_database_unavailable"):
                sync.bind_policy_locked(self.exemptions, self.store)
        sentinel = self.connection(self.db)
        intent = dict(sentinel.execute("SELECT * FROM adaptive_exemption_binding WHERE singleton=1").fetchone())
        self.assertEqual((intent["policy_instance_id"], intent["policy_logon_id"], intent["store_id"]),
                         (guard.binding.instance_id, guard.binding.logon_id, before["store_id"]))
        self.assertEqual(dict(conn.execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone()), before)
        self.assertEqual(self.rows(), leases)
        # Only the exemption transaction rolled back. The earlier sentinel
        # intent remains authoritative and prevents reopening the public facade.
        with self.assertRaises(sync.ExemptionSyncError):
            sync.grant_record(self.exemptions, self.record(777), now=NOW,
                              policy_factory=lambda path: self.store)
        with self.assertRaises(sync.ExemptionSyncError):
            sync.revoke_record(self.exemptions, row["id"], now=NOW + 1,
                               policy_factory=lambda path: self.store)
        self.assertEqual(dict(conn.execute("SELECT * FROM exemption_sync WHERE singleton=1").fetchone()), before)
        self.assertEqual(self.rows(), leases)
        self.assertEqual(dict(sentinel.execute("SELECT * FROM adaptive_exemption_binding WHERE singleton=1").fetchone()), intent)
        conn.execute("DROP TRIGGER fixture_reject_binding")
        binding = self.bind()
        repaired = self.snapshot()
        self.assertEqual(repaired.binding, binding)
        self.assertEqual([lease["id"] for lease in repaired.leases], [row["id"]])
        self.assertEqual(conn.execute("SELECT store_id FROM exemption_sync WHERE singleton=1").fetchone()[0], intent["store_id"])
        self.assertEqual(self.rows(), leases)
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE exemptions SET reason=? WHERE id=?", ("old writer after bind", row["id"]))
        self.assertEqual(sync.revoke_record(self.exemptions, row["id"], now=NOW + 1,
                                           policy_factory=self.factory), 1)

    def test_exemption_transactions_do_not_overlap_lifecycle_write_transaction(self):
        original_transaction = self.store._transaction
        original_connection = self.store._connection
        original_connect = sync._connect
        lifecycle_transaction_active = False
        observations = []
        exemption_connections = []
        lifecycle_connections = []
        overlaps = []
        bound_writes = []

        def transaction_open(connection):
            try:
                return connection.in_transaction
            except sqlite3.ProgrammingError:
                return False  # A closed connection has released its transaction.

        @contextmanager
        def tracked_lifecycle_connection():
            with original_connection() as connection:
                lifecycle_connections.append(connection)
                yield connection

        @contextmanager
        def tracked_transaction():
            nonlocal lifecycle_transaction_active
            for connection in exemption_connections:
                if transaction_open(connection):
                    overlaps.append("exemption transaction live before lifecycle transaction")
            lifecycle_transaction_active = True
            try:
                with original_transaction() as conn:
                    yield conn
            finally:
                lifecycle_transaction_active = False

        def tracked_connect(path, **kwargs):
            resolved = Path(path).resolve()
            if resolved == self.exemptions.path.resolve():
                self.assertFalse(lifecycle_transaction_active)
                self.assertFalse(any(transaction_open(conn) for conn in lifecycle_connections))
                self.assert_writer_unlocked(self.db)
                observations.append("exemption_connection_outside_lifecycle_transaction")
            elif resolved == self.db.resolve():
                self.assertFalse(any(transaction_open(conn) for conn in exemption_connections))
            connection = original_connect(path, **kwargs)
            if resolved == self.db.resolve():
                lifecycle_connections.append(connection)
            if resolved == self.exemptions.path.resolve():
                exemption_connections.append(connection)

                def trace(statement):
                    normalized = statement.lstrip().upper()
                    lifecycle_active = lifecycle_transaction_active or any(transaction_open(conn) for conn in lifecycle_connections)
                    if lifecycle_active and (normalized.startswith("BEGIN") or connection.in_transaction):
                        overlaps.append("exemption transaction entered during lifecycle transaction")
                    if normalized.startswith(("INSERT INTO EXEMPTIONS", "UPDATE EXEMPTIONS")):
                        bound_writes.append(self.provider.active)

                connection.set_trace_callback(trace)
            return connection

        row = self.record()
        with patch.object(self.store, "_transaction", tracked_transaction), \
                patch.object(self.store, "_connection", tracked_lifecycle_connection), \
                patch.object(sync, "_connect", tracked_connect):
            self.bind()
            sync.grant_record(self.exemptions, row, now=NOW, policy_factory=self.factory)
            sync.revoke_record(self.exemptions, row["id"], now=NOW + 1, policy_factory=self.factory)
        self.assertGreaterEqual(len(observations), 2)
        self.assertEqual(overlaps, [])
        self.assertTrue(bound_writes)
        self.assertTrue(all(bound_writes))

    def test_failed_after_unlock_recovery_keeps_committed_grant_pending(self):
        self.bind()
        notices = []

        def fail_recovery(notice):
            self.assertFalse(self.provider.active)
            self.assertIsNone(self.store._policy.current_guard())
            notices.append(notice)
            raise RuntimeError("fixture_recovery_unavailable")

        row = self.record()
        result = sync.grant_record(self.exemptions, row, now=NOW,
                                   policy_factory=self.factory, after_unlock=fail_recovery)
        self.assertEqual((result["grant_state"], result["enforcement_state"], result["recovery_request_state"]),
                         ("recorded", "restore_pending", "failed"))
        self.assertEqual(self.rows()[0]["id"], row["id"])
        self.assertEqual(self.rows()[0]["expires_at"], row["expires_at"])
        self.assertIsNone(self.rows()[0]["revoked_at"])
        self.assertEqual(len(notices), 1)
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            notices[0].changed = False

    def test_failed_revoke_callback_reports_that_the_revocation_already_committed(self):
        row = self.record()
        sync.grant_record(self.exemptions, row, now=NOW)
        self.bind()
        observations = []

        def fail_recovery(notice):
            # Do not put assertions in this deliberately failing callback:
            # the facade must wrap its exception after the committed mutation.
            observations.append((self.provider.active, self.store._policy.current_guard(),
                                 notice.operation, notice.exemption_id, notice.changed))
            raise RuntimeError("fixture_recovery_unavailable")

        with self.assertRaises(sync.ExemptionSyncError) as failed:
            sync.revoke_record(self.exemptions, row["id"], now=NOW + 1,
                               policy_factory=self.factory, after_unlock=fail_recovery)
        self.assertEqual(failed.exception.committed_count, 1)
        self.assertEqual(self.rows()[0]["revoked_at"], NOW + 1)
        self.assertEqual(observations, [(False, None, "revoke", row["id"], True)])


if __name__ == "__main__":
    unittest.main()
