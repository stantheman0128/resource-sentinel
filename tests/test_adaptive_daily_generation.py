"""Isolated source/generation invariants, with explicit synthetic identity."""
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import Mock, patch
import uuid

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity


class DailyGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        location = patch.object(generation, "daily_locations", return_value=(self.root, self.root))
        location.start()
        self.addCleanup(location.stop)
        (self.root / "config.json").write_text(json.dumps({
            "admission_policy": "resource-v2", "local_allocatable_ram_gib": 58}))
        for relative in generation.REQUIRED_PATHS:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# isolated source fixture\n", encoding="utf-8")
        self.manifest = generation.SourceManifest.capture(self.root)
        self.db = self.root / "sentinel.db"
        self.conn = sqlite3.connect(self.db)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        self.conn.executescript("""
            CREATE TABLE adaptive_runtime(singleton INTEGER PRIMARY KEY, mode TEXT,
                admission_barrier TEXT, policy_entry_nonce TEXT,
                policy_instance_id TEXT, policy_logon_id TEXT);
            INSERT INTO adaptive_runtime VALUES(1,'off','NONE',NULL,'policy','S-1-5-5-1-2');
            CREATE TABLE reservations(id TEXT);
            CREATE TABLE worker_reservations(id TEXT);
            CREATE TABLE workers(id TEXT);
            CREATE TABLE queue(id TEXT);
            CREATE TABLE managed_executions(execution_id TEXT);
        """)
        self.identity = ProcessIdentity(123, 123456, "S-1-5-5-1-2")
        self.process = Mock(identity=self.identity)
        self.process.observe.return_value = SimpleNamespace(status=IdentityStatus.ALIVE, identity=self.identity)
        self.owner = generation.DailyGenerationOwner(_token=generation._TOKEN,
            process=self.process, cohort=Mock(spec=["assert_retired", "assert_retained_retired", "close"]),
            manifest=self.manifest,
            source_root=self.root, ledger_path=self.db)
        self.addCleanup(lambda: generation._LOCAL_GENERATIONS.pop(self.owner.generation, None))
        self.guard = SimpleNamespace(binding=SimpleNamespace(instance_id="policy", logon_id=self.identity.logon_id))
        # Explicit unit-only POLICY seam. Mock's implicit assert_* names are
        # intentionally unavailable; declare the real provider operations and
        # require the exact retained fixture guard on every call.
        self.policy = Mock(spec=["assert_held", "revalidate", "current_guard"])
        self.policy.assert_held.side_effect = lambda guard: self.assertIs(guard, self.guard)
        self.policy.revalidate.side_effect = lambda conn, guard: self.assertIs(guard, self.guard)
        self.policy.current_guard.return_value = None

    def install(self, *, acknowledge=True):
        with patch.object(generation, "verify_import_provenance", return_value=self.root):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
        writer = sqlite3.connect(self.db)
        writer.row_factory = sqlite3.Row
        self.addCleanup(writer.close)
        writer.execute("BEGIN IMMEDIATE")
        self.owner.install_locked(writer, policy=self.policy, guard=self.guard)
        writer.commit()
        self.owner.settle_install_connection()
        if acknowledge:
            self.owner.acknowledge_install(conn=self.conn)

    def test_manifest_roundtrip_and_digest(self):
        self.assertEqual(generation.SourceManifest.from_dict(self.manifest.to_dict()), self.manifest)
        self.assertEqual(self.manifest.verify(self.root), self.root.resolve())
        self.assertEqual(len(self.manifest.digest), 64)

    def test_ledger_identity_requires_the_opened_file_object(self):
        actual = self.db.stat()
        changed = SimpleNamespace(st_mode=actual.st_mode, st_dev=actual.st_dev,
                                  st_ino=actual.st_ino + 1)
        with patch.object(generation.os, "fstat", return_value=changed), \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "identity_changed"):
            generation._ledger_identity(self.db)

    def test_ledger_reparse_metadata_refuses_before_open(self):
        actual = self.db.stat()
        redirected = SimpleNamespace(st_mode=actual.st_mode, st_file_attributes=0x400)
        with patch.object(Path, "lstat", return_value=redirected), \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "reparse_unsupported"):
            generation._ledger_identity(self.db)

    def test_manifest_rejects_incomplete_or_duplicate_entries(self):
        for entries in (self.manifest.entries[:-1], self.manifest.entries + self.manifest.entries[-1:]):
            with self.subTest(entries=len(entries)), self.assertRaises(generation.DailyGenerationUnavailable):
                generation.SourceManifest(entries)

    def test_manifest_rejects_unknown_fields(self):
        value = self.manifest.to_dict()
        value["allow"] = True
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "manifest_invalid"):
            generation.SourceManifest.from_dict(value)

    def test_manifest_rejects_path_escape(self):
        value = self.manifest.to_dict()
        value["files"].append({"path": "../escape.py", "sha256": "a" * 64, "size": 0})
        value["files"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "path_invalid"):
            generation.SourceManifest.from_dict(value)

    def test_changed_source_is_not_a_generation_match(self):
        (self.root / "sentinel/coordinator.py").write_text("# changed\n")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_mismatch"):
            self.manifest.verify(self.root)

    def test_additional_entrypoint_is_not_ignored(self):
        (self.root / "scripts/new-writer.py").write_text("pass\n")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "closure_changed"):
            self.manifest.verify(self.root)

    def test_loaded_stale_code_refuses_even_when_current_file_matches(self):
        path = self.root / "sentinel/coordinator.py"
        old_source = "def admit():\n    return 'old'\n"
        new_source = "def admit():\n    return 'new'\n"
        module = ModuleType("sentinel.coordinator")
        module.__file__ = str(path)
        exec(compile(old_source, str(path), "exec"), module.__dict__)
        path.write_text(new_source)
        manifest = generation.SourceManifest.capture(self.root)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "loaded_code_generation_mismatch"):
            generation.verify_loaded_source(manifest, self.root, modules={module.__name__: module})

    def test_matching_loaded_functions_are_accepted(self):
        path = self.root / "sentinel/coordinator.py"
        source = "def admit():\n    return 42\n"
        module = ModuleType("sentinel.coordinator")
        module.__file__ = str(path)
        exec(compile(source, str(path), "exec"), module.__dict__)
        path.write_text(source)
        manifest = generation.SourceManifest.capture(self.root)
        self.assertEqual(generation.verify_loaded_source(manifest, self.root,
            modules={module.__name__: module}), self.root.resolve())

    def test_matching_file_at_foreign_loaded_origin_refuses(self):
        module = ModuleType("sentinel.other")
        module.__file__ = str(self.root.parent / "other.py")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "origin_mismatch"):
            generation.verify_loaded_source(self.manifest, self.root, modules={module.__name__: module})

    def test_second_source_read_remains_bound_after_manifest_verification(self):
        self.manifest.verify(self.root)
        (self.root / "sentinel/coordinator.py").write_text("# changed after first verification\n")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_mismatch"):
            generation._manifest_bound_sources(self.manifest, self.root, ("sentinel/coordinator.py",))

    def test_no_generation_is_read_only_legacy_compatibility(self):
        before = self.conn.total_changes
        self.assertIsNone(generation.prepare_connection(self.conn, role="coordinator", db_path=self.db))
        self.assertEqual(self.conn.total_changes, before)
        self.assertIsNone(generation.read_generation(self.conn))

    def test_connection_preparation_inside_transaction_is_rejected(self):
        self.conn.execute("BEGIN")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_invalid"):
            generation.prepare_connection(self.conn, role="coordinator", db_path=self.db)
        self.conn.rollback()

    def test_invalid_role_is_rejected_even_without_generation(self):
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "scope_invalid"):
            generation.prepare_connection(self.conn, role="unknown", db_path=self.db)

    def test_install_requires_original_prepared_owner(self):
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "not_prepared"):
            self.owner.install_locked(self.conn, policy=self.policy, guard=self.guard)

    def test_cohort_retirement_failure_prevents_install_preparation(self):
        self.owner.cohort.assert_retired.side_effect = RuntimeError("synthetic unknown")
        with patch.object(generation, "verify_import_provenance"), self.assertRaises(RuntimeError):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
        self.assertFalse(getattr(self.owner, "_prepared_install", False))

    def test_owner_unknown_prevents_preparation(self):
        self.process.observe.return_value.status = IdentityStatus.UNKNOWN
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "owner_unavailable"):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)

    def test_existing_legacy_allocation_refuses_cutover(self):
        self.conn.execute("INSERT INTO reservations VALUES('existing')")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "allocations_not_empty"):
            self.install()
        self.conn.rollback()
        self.assertIsNone(generation.read_generation(self.conn))

    def test_existing_queue_refuses_cutover(self):
        self.conn.execute("INSERT INTO queue VALUES('queued')")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "allocations_not_empty"):
            self.install()
        self.conn.rollback()

    def test_any_managed_history_refuses_cold_adoption(self):
        self.conn.execute("INSERT INTO managed_executions VALUES('finished-but-no-native-witness')")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "history_unverified"):
            self.install()
        self.conn.rollback()

    def test_active_mode_cannot_be_migration_shortcut(self):
        self.conn.execute("UPDATE adaptive_runtime SET mode='canary'")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "requires_off"):
            self.install()
        self.conn.rollback()

    def test_old_connection_cannot_write_after_generation_install(self):
        self.install()
        old = sqlite3.connect(self.db)
        try:
            for table in generation.CAPACITY_TABLES:
                with self.subTest(table=table), self.assertRaises(sqlite3.OperationalError):
                    old.execute(f"INSERT INTO {table} VALUES('old')")
                old.rollback()
        finally:
            old.close()

    def test_changed_generation_rejects_original_connection(self):
        self.install()
        self.conn.create_function("sentinel_daily_generation", 0, lambda: self.owner.generation)
        self.conn.execute("UPDATE adaptive_daily_generation SET generation=?", (str(uuid.uuid4()),))
        self.conn.commit()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "daily_generation_required"):
            self.conn.execute("INSERT INTO reservations VALUES('stale')")
        self.conn.rollback()

    def test_guarded_generation_connection_writes_only_its_generation(self):
        self.install()
        fresh = sqlite3.connect(self.db)
        try:
            with patch.object(generation, "verify_import_provenance"), \
                    patch.object(generation.VerifiedProcess, "open", return_value=self.process):
                self.assertEqual(generation.prepare_connection(fresh, role="coordinator", db_path=self.db),
                                 self.owner.generation)
            fresh.execute("INSERT INTO reservations VALUES('new')")
            fresh.commit()
            self.assertEqual(fresh.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
        finally:
            fresh.close()

    def test_dead_generation_owner_cannot_authorize_new_connection(self):
        self.install()
        self.process.observe.return_value.status = IdentityStatus.DEAD
        fresh = sqlite3.connect(self.db)
        try:
            with patch.object(generation, "verify_import_provenance"), \
                    patch.object(generation.VerifiedProcess, "open", return_value=self.process), \
                    self.assertRaisesRegex(generation.DailyGenerationUnavailable, "owner_unavailable"):
                generation.prepare_connection(fresh, role="coordinator", db_path=self.db)
        finally:
            fresh.close()

    def test_draining_generation_refuses_new_connection(self):
        self.install()
        self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "draining"):
            generation.prepare_connection(self.conn, role="coordinator", db_path=self.db)

    def test_ack_requires_commit_and_original_policy_cleanup(self):
        self.install(acknowledge=False)
        self.policy.current_guard.return_value = self.guard
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "policy_unsettled"):
            self.owner.acknowledge_install(conn=self.conn)
        self.assertFalse(self.owner._activated)

    def test_pending_policy_nonce_blocks_install_ack(self):
        self.install(acknowledge=False)
        self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce='pending'")
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "policy_unsettled"):
            self.owner.acknowledge_install(conn=self.conn)

    def test_activated_owner_cannot_discard_custody(self):
        self.install()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "custody_required"):
            self.owner.close_unactivated()
        self.process.close.assert_not_called()

    def test_install_attempt_without_ack_cannot_discard_custody(self):
        self.install(acknowledge=False)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "custody_required"):
            self.owner.close_unactivated()

    def test_ready_requires_live_original_owner_and_unchanged_generation(self):
        self.install()
        with patch.object(generation, "verify_import_provenance"):
            self.assertIsNone(self.owner.assert_ready())
            self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
            self.conn.commit()
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_changed"):
                self.owner.assert_ready()

    def test_public_constructor_cannot_turn_manifest_into_owner(self):
        with self.assertRaisesRegex(TypeError, "capture"):
            generation.DailyGenerationOwner(manifest=self.manifest)

    def test_later_prepare_failure_clears_previous_install_permission(self):
        with patch.object(generation, "verify_import_provenance"):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
            self.owner.cohort.assert_retired.side_effect = RuntimeError("synthetic unknown")
            with self.assertRaises(RuntimeError):
                self.owner.prepare_install(policy=self.policy, guard=self.guard)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "not_prepared"):
            self.owner.install_locked(self.conn, policy=self.policy, guard=self.guard)

    def test_preparation_is_bound_to_exact_original_guard(self):
        with patch.object(generation, "verify_import_provenance"):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
        other = SimpleNamespace(binding=self.guard.binding)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "not_prepared"):
            self.owner.install_locked(self.conn, policy=self.policy, guard=other)

    def test_first_sql_mutation_exception_retains_install_custody(self):
        with patch.object(generation, "verify_import_provenance"):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
        class FailingConnection:
            in_transaction = True
            def execute(inner, sql, *arguments):
                if sql.startswith("CREATE TABLE adaptive_daily_generation"):
                    raise RuntimeError("synthetic lost SQL outcome")
                return self.conn.execute(sql, *arguments)
        with self.assertRaisesRegex(RuntimeError, "lost SQL"):
            self.owner.install_locked(FailingConnection(), policy=self.policy, guard=self.guard)
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "custody_required"):
            self.owner.close_unactivated()

    def test_ack_rejects_unclosed_original_install_connection(self):
        with patch.object(generation, "verify_import_provenance"):
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
        self.conn.execute("BEGIN IMMEDIATE")
        self.owner.install_locked(self.conn, policy=self.policy, guard=self.guard)
        self.conn.commit()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "unsettled"):
            self.owner.acknowledge_install(conn=self.conn)

    def test_unknown_install_connection_close_is_not_retried(self):
        self.owner._install_attempted = True
        self.owner._install_connection_closed = False
        self.owner._install_close_unknown = False
        self.owner._install_policy = self.policy
        connection = Mock(in_transaction=False)
        connection.close.side_effect = RuntimeError("synthetic close unknown")
        self.owner._install_connection = connection
        with self.assertRaises(RuntimeError):
            self.owner.settle_install_connection()
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "close_unknown"):
            self.owner.settle_install_connection()
        self.assertEqual(connection.close.call_count, 1)

    def test_readiness_only_observes_frozen_old_cohort(self):
        self.install()
        self.owner.cohort.reset_mock()
        with patch.object(generation, "verify_import_provenance"):
            self.owner.assert_ready()
        self.owner.cohort.assert_retained_retired.assert_called_once_with()
        self.owner.cohort.assert_retired.assert_not_called()

    def test_install_commit_without_cleanup_ack_does_not_authorize_capacity(self):
        self.install(acknowledge=False)
        fresh = sqlite3.connect(self.db)
        try:
            with patch.object(generation, "verify_import_provenance"), \
                    self.assertRaisesRegex(generation.DailyGenerationUnavailable, "not_activated"):
                generation.prepare_connection(fresh, role="coordinator", db_path=self.db)
            with self.assertRaises(sqlite3.OperationalError):
                fresh.execute("INSERT INTO reservations VALUES('too-early')")
        finally:
            fresh.close()

    def test_original_install_policy_cleanup_has_no_capacity_authority(self):
        self.install(acknowledge=False)
        cleanup = sqlite3.connect(self.db, isolation_level=None)
        try:
            with patch.object(generation, "verify_import_provenance"):
                self.assertIsNone(generation.prepare_connection(cleanup, role="lifecycle", db_path=self.db))
            cleanup.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL WHERE singleton=1")
            with self.assertRaises(sqlite3.DatabaseError):
                cleanup.execute("INSERT INTO reservations VALUES('forbidden')")
            with self.assertRaises(sqlite3.DatabaseError):
                cleanup.execute("UPDATE adaptive_runtime SET admission_barrier='NONE'")
        finally:
            cleanup.close()

    def test_configuration_drift_cannot_keep_old_readiness(self):
        self.install()
        (self.root / "config.json").write_text(json.dumps({
            "admission_policy": "resource-v2", "local_allocatable_ram_gib": 59}))
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "policy_mismatch"):
            self.owner.assert_ready()

    def test_ordinary_policy_nonce_does_not_invalidate_acknowledged_owner(self):
        self.install()
        self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce='another-live-operation'")
        self.conn.commit()
        with patch.object(generation, "verify_import_provenance"):
            self.assertIsNone(self.owner.assert_ready())

    def test_readiness_rejects_changed_endpoint_binding(self):
        self.install()
        self.conn.execute("UPDATE adaptive_daily_generation SET readiness_instance_id=?", (str(uuid.uuid4()),))
        self.conn.commit()
        with patch.object(generation, "verify_import_provenance"), \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_changed"):
            self.owner.assert_ready()

    def test_constructor_failure_retains_the_original_process(self):
        with patch.object(generation, "verify_import_provenance", return_value=self.root), \
                patch.object(generation.VerifiedProcess, "current", return_value=self.process), \
                patch.object(generation, "_ledger_identity", side_effect=RuntimeError("synthetic identity failure")):
            with self.assertRaisesRegex(RuntimeError, "identity failure") as failure:
                generation.DailyGenerationOwner.capture(manifest=self.manifest,
                    source_root=self.root, ledger_path=self.db)
        self.assertIs(failure.exception.daily_generation_process, self.process)
        self.process.close.assert_not_called()

    def test_alternate_location_refuses_before_native_cohort_capture(self):
        with patch.object(generation.VerifiedProcess, "current") as native, \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "location_mismatch"):
            generation.DailyGenerationOwner.capture(manifest=self.manifest,
                source_root=self.root, ledger_path=self.root / "alternate.db")
        native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
