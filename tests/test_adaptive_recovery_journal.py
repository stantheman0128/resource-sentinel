"""Filesystem/fault fixtures only: no native Job or recovery capability proof."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields
import json
from pathlib import Path
import threading
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import (
    ContractViolation, CpuControl, CpuControlMode, MAX_MESSAGE_BYTES,
    PendingIntent, ProcessIdentity, RecoveryManifest, ResourceDemand,
)
from tests.windows import adaptive_recovery_journal as journal_module


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
CAP = CpuControl(CpuControlMode.HARD_CAP, 2500)
OTHER_CAP = CpuControl(CpuControlMode.HARD_CAP, 4000)
WRAPPER = ProcessIdentity(4101, 134343072000000001, "fixture-logon")
GUARDIAN = ProcessIdentity(4102, 134343072000000002, "fixture-logon")
ROOT = ProcessIdentity(4103, 134343072000000003, "fixture-logon")
FLOOR = ResourceDemand(2.0, 2 << 20, 3 << 20, 1)


class HeldScope:
    """A real shared mutex, with ownership confined to the acquiring thread."""

    def __init__(self, record, *, lock=None, observed=DISABLED):
        self.execution_id = record.execution_id
        self.creation_nonce = record.creation_nonce
        self.lock = threading.Lock() if lock is None else lock
        self.observed = observed
        self.thread_id = None
        self.valid = True
        self.queries = 0
        self.checks = 0

    @contextmanager
    def held(self):
        if not self.lock.acquire(timeout=2):
            raise AssertionError("fixture_mutex_timeout")
        self.thread_id = threading.get_ident()
        try:
            yield self
        finally:
            self.thread_id = None
            self.lock.release()

    def assert_held(self):
        self.checks += 1
        if (not self.valid or not self.lock.locked() or
                self.thread_id != threading.get_ident()):
            raise RuntimeError("fixture_scope_not_held")

    def query_cpu_control(self):
        self.assert_held()
        self.queries += 1
        return self.observed


def record(**changes):
    nonce = uuid4().hex
    values = dict(
        execution_id=str(uuid4()),
        job_name="Local\\ResourceSentinel.Test.Job." + nonce,
        creation_nonce=nonce,
        wrapper_identity=WRAPPER,
        root_identity=None,
        guardian_identity=GUARDIAN,
        guardian_epoch="fixture-guardian-epoch",
        original=DISABLED,
        last_applied=None,
        pending_intent=None,
        allocated_floor=FLOOR,
        manifest_seq=0,
    )
    values.update(changes)
    return journal_module.TestRecoveryRecord.create(**values)


def successor(old, **changes):
    values = {item.name: getattr(old, item.name) for item in fields(old)
              if item.name != "manifest_hash"}
    values["manifest_seq"] = old.manifest_seq + 1
    values.update(changes)
    return journal_module.TestRecoveryRecord.create(**values)


class RecoveryJournalTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="sentinel-journal-test-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.journal = journal_module.TestRecoveryJournal(self.directory)
        self.base = record()
        self.scope = HeldScope(self.base)

    def path(self, item=None):
        item = self.base if item is None else item
        return self.directory / (item.execution_id + ".json")

    def read(self, item=None):
        item = self.base if item is None else item
        return self.journal.read(item.execution_id, creation_nonce=item.creation_nonce)

    def create(self):
        with self.scope.held():
            self.journal.create(self.base, writer_scope=self.scope)
        self.assertEqual(self.read(), self.base)
        return self.base

    def publish(self, old, candidate, scope=None):
        scope = self.scope if scope is None else scope
        with scope.held():
            return self.journal.publish(
                candidate, expected_seq=old.manifest_seq,
                expected_hash=old.manifest_hash, writer_scope=scope,
            )

    def assert_rejected(self, old, candidate, scope=None):
        before = self.path().read_bytes()
        with self.assertRaises(journal_module.TestJournalError):
            self.publish(old, candidate, scope)
        self.assertEqual(self.path().read_bytes(), before)
        self.assertEqual(self.read(), old)

    def pending(self):
        old = self.create()
        candidate = successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP))
        self.publish(old, candidate)
        self.assertEqual(self.read(), candidate)
        return candidate

    def test_fixture_record_roundtrip_frozen_and_distinct_from_production_schema(self):
        payload = self.base.to_json()
        self.assertEqual(journal_module.TestRecoveryRecord.from_json(payload), self.base)
        decoded = json.loads(payload)
        self.assertEqual(decoded["fixture_schema_version"], 1)
        self.assertIs(decoded["test_only"], True)
        self.assertNotIn("schema_version", decoded)
        self.assertEqual(self.base.job_name,
                         "Local\\ResourceSentinel.Test.Job." + self.base.creation_nonce)
        with self.assertRaises(FrozenInstanceError):
            self.base.manifest_seq = 9
        with self.assertRaises(ContractViolation):
            RecoveryManifest.from_json(payload)

    def test_fixture_record_rejects_production_job_namespace(self):
        production_name = ("Local\\ResourceSentinel.Job." + self.base.execution_id +
                           "." + self.base.creation_nonce)
        with self.assertRaises((ContractViolation, journal_module.TestJournalError)):
            successor(self.base, job_name=production_name)

    def test_fixture_markers_and_original_disabled_cannot_be_changed(self):
        for change in (dict(fixture_schema_version=2), dict(fixture_schema_version=True),
                       dict(test_only=False), dict(original=CAP)):
            with self.subTest(changes=tuple(change)):
                with self.assertRaises(journal_module.TestJournalError):
                    successor(self.base, **change)

    def test_create_records_disabled_pre_job_baseline_without_querying_job(self):
        self.scope.observed = OTHER_CAP
        self.create()
        self.assertEqual(self.scope.queries, 0)
        self.assertGreater(self.scope.checks, 0)
        self.assertEqual({item.name for item in self.directory.iterdir()}, {self.path().name})

    def test_create_requires_zero_sequence_and_no_root_intent_or_applied_state(self):
        alternatives = (
            dict(manifest_seq=1), dict(root_identity=ROOT), dict(last_applied=DISABLED),
            dict(pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP)),
        )
        for changes in alternatives:
            with self.subTest(changes=tuple(changes)):
                candidate = successor(self.base, **{"manifest_seq": 0, **changes})
                with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
                    self.journal.create(candidate, writer_scope=self.scope)
                self.assertFalse(self.path().exists())

    def test_relative_or_missing_directory_is_rejected_without_creation(self):
        for directory in (Path("relative-journal-fixture"), self.directory / "missing"):
            with self.subTest(directory=directory.name):
                with self.assertRaises(journal_module.TestJournalError):
                    journal_module.TestRecoveryJournal(directory)
        self.assertFalse((self.directory / "missing").exists())

    def test_create_preserves_existing_unknown_file(self):
        original = b"unknown-fixture-content"
        self.path().write_bytes(original)
        with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
            self.journal.create(self.base, writer_scope=self.scope)
        self.assertEqual(self.path().read_bytes(), original)

    def test_create_collision_preserves_valid_record_and_does_not_query(self):
        self.create()
        before = self.path().read_bytes()
        with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
            self.journal.create(self.base, writer_scope=self.scope)
        self.assertEqual(self.path().read_bytes(), before)
        self.assertEqual(self.scope.queries, 0)

    def test_read_rejects_wrong_nonce_and_invalid_execution_selector(self):
        self.create()
        with self.assertRaises(journal_module.TestJournalError):
            self.journal.read(self.base.execution_id, creation_nonce="f" * 32)
        for execution_id in ("../escape", "not-a-uuid", "A0000000-0000-4000-8000-000000000001"):
            with self.subTest(execution_id=execution_id):
                with self.assertRaises(journal_module.TestJournalError):
                    self.journal.read(execution_id, creation_nonce=self.base.creation_nonce)
        self.assertEqual(self.read(), self.base)

    def test_scope_must_be_held_by_calling_thread_and_match_record(self):
        with self.assertRaises(journal_module.TestJournalError):
            self.journal.create(self.base, writer_scope=self.scope)
        self.assertFalse(self.path().exists())
        for field in ("execution_id", "creation_nonce"):
            scope = HeldScope(self.base)
            setattr(scope, field, str(uuid4()) if field == "execution_id" else uuid4().hex)
            with self.subTest(field=field), scope.held():
                with self.assertRaises(journal_module.TestJournalError):
                    self.journal.create(self.base, writer_scope=scope)
        self.assertFalse(self.path().exists())

    def test_initial_create_from_other_thread_cannot_borrow_held_scope(self):
        errors = []

        def borrower():
            try:
                self.journal.create(self.base, writer_scope=self.scope)
            except Exception as error:
                errors.append(error)

        with self.scope.held():
            worker = threading.Thread(target=borrower)
            worker.start()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive(), "borrowed scope must reject without waiting")
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], journal_module.TestJournalError)
        self.assertFalse(self.path().exists())

    def test_publish_requires_exact_sequence_hash_and_one_step_increment(self):
        old = self.create()
        candidate = successor(old)
        for sequence, digest in ((old.manifest_seq + 1, old.manifest_hash),
                                 (old.manifest_seq, "f" * 64)):
            with self.subTest(sequence=sequence, digest_matches=digest == old.manifest_hash):
                with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
                    self.journal.publish(candidate, expected_seq=sequence,
                                         expected_hash=digest, writer_scope=self.scope)
                self.assertEqual(self.read(), old)
        for sequence in (old.manifest_seq, old.manifest_seq + 2):
            with self.subTest(candidate_sequence=sequence):
                self.assert_rejected(old, successor(old, manifest_seq=sequence))

    def test_immutable_owner_epoch_and_nonce_changes_cannot_replace_record(self):
        old = self.create()
        nonce = uuid4().hex
        changes = (
            dict(wrapper_identity=ProcessIdentity(4201, WRAPPER.created_filetime_100ns, WRAPPER.logon_id)),
            dict(guardian_identity=ProcessIdentity(4202, GUARDIAN.created_filetime_100ns, GUARDIAN.logon_id)),
            dict(guardian_epoch="other-fixture-epoch"),
            dict(creation_nonce=nonce, job_name="Local\\ResourceSentinel.Test.Job." + nonce),
        )
        for change in changes:
            with self.subTest(changes=tuple(change)):
                self.assert_rejected(old, successor(old, **change))

    def test_floor_increases_and_first_root_binding_succeed_but_cannot_reverse(self):
        old = self.create()
        larger = ResourceDemand(3.0, 3 << 20, 4 << 20, 2)
        bound = successor(old, root_identity=ROOT, allocated_floor=larger)
        self.publish(old, bound)
        self.assertEqual(self.read(), bound)
        self.assertGreaterEqual(self.scope.queries, 2)
        for root in (None, ProcessIdentity(ROOT.pid + 1, ROOT.created_filetime_100ns, ROOT.logon_id)):
            with self.subTest(root=root):
                self.assert_rejected(bound, successor(bound, root_identity=root))
        for demand in (ResourceDemand(2.9, 3 << 20, 4 << 20, 2),
                       ResourceDemand(3.0, (3 << 20) - 1, 4 << 20, 2),
                       ResourceDemand(3.0, 3 << 20, (4 << 20) - 1, 2),
                       ResourceDemand(3.0, 3 << 20, 4 << 20, 1)):
            with self.subTest(demand=demand):
                self.assert_rejected(bound, successor(bound, allocated_floor=demand))

    def test_two_serialized_writers_from_same_revision_cannot_lose_an_update(self):
        old = self.create()
        candidates = (
            successor(old, allocated_floor=ResourceDemand(3.0, 2 << 20, 3 << 20, 1)),
            successor(old, allocated_floor=ResourceDemand(4.0, 2 << 20, 3 << 20, 1)),
        )
        gate = threading.Barrier(3)
        lock = threading.Lock()
        outcomes = []

        def writer(candidate):
            scope = HeldScope(old, lock=lock)
            try:
                gate.wait(timeout=2)
                self.publish(old, candidate, scope)
            except Exception as error:
                outcomes.append(("error", error))
            else:
                outcomes.append(("published", candidate))

        workers = [threading.Thread(target=writer, args=(candidate,)) for candidate in candidates]
        for worker in workers:
            worker.start()
        gate.wait(timeout=2)
        for worker in workers:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive(), "journal fixture writer did not finish")
        successes = [value for outcome, value in outcomes if outcome == "published"]
        failures = [value for outcome, value in outcomes if outcome == "error"]
        self.assertEqual(len(successes), 1, outcomes)
        self.assertEqual(len(failures), 1, outcomes)
        self.assertIsInstance(failures[0], journal_module.TestJournalError)
        self.assertEqual(self.read(), successes[0])
        self.assertEqual(self.read().manifest_seq, 1)

    def test_intent_then_observed_apply_then_observed_restore_are_recorded(self):
        pending = self.pending()
        self.scope.observed = CAP
        applied = successor(pending, pending_intent=None, last_applied=CAP)
        self.publish(pending, applied)
        self.assertEqual(self.read(), applied)
        self.scope.observed = DISABLED
        restored = successor(applied, last_applied=DISABLED)
        self.publish(applied, restored)
        self.assertEqual(self.read(), restored)

    def test_pending_intent_can_settle_back_to_observed_old_disabled(self):
        pending = self.pending()
        settled = successor(pending, pending_intent=None, last_applied=DISABLED)
        self.publish(pending, settled)
        self.assertEqual(self.read(), settled)

    def test_pending_cap_transition_can_settle_to_verified_original_disabled(self):
        pending = self.pending()
        self.scope.observed = CAP
        applied = successor(pending, pending_intent=None, last_applied=CAP)
        self.publish(pending, applied)
        transition = successor(applied, pending_intent=PendingIntent(str(uuid4()), CAP, OTHER_CAP))
        self.publish(applied, transition)
        self.scope.observed = DISABLED
        restored = successor(transition, pending_intent=None, last_applied=DISABLED)
        self.publish(transition, restored)
        self.assertEqual(self.read(), restored)

    def test_new_intent_requires_observed_old_and_different_target(self):
        old = self.create()
        intent = successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP))
        self.scope.observed = CAP
        self.assert_rejected(old, intent)
        self.scope.observed = DISABLED
        unchanged = successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, DISABLED))
        self.assert_rejected(old, unchanged)

    def test_unresolved_pending_cannot_be_replaced_or_cleared_without_query_match(self):
        pending = self.pending()
        replacement = successor(pending, pending_intent=PendingIntent(str(uuid4()), DISABLED, OTHER_CAP))
        self.assert_rejected(pending, replacement)
        self.assert_rejected(pending, successor(pending, pending_intent=None, last_applied=CAP))
        self.assert_rejected(pending, successor(pending, pending_intent=None, last_applied=None))
        self.scope.observed = OTHER_CAP
        self.assert_rejected(pending, successor(pending, pending_intent=None, last_applied=OTHER_CAP))

    def test_preserved_pending_metadata_requires_observed_known_control(self):
        pending = self.pending()
        candidate = successor(pending, root_identity=ROOT)
        self.scope.observed = OTHER_CAP
        self.assert_rejected(pending, candidate)
        self.scope.observed = CAP
        self.publish(pending, candidate)
        self.assertEqual(self.read(), candidate)
        self.assertEqual(self.read().pending_intent, pending.pending_intent)

    def test_cap_cannot_be_invented_from_query_without_prior_intent(self):
        old = self.create()
        self.scope.observed = CAP
        self.assert_rejected(old, successor(old, last_applied=CAP))
        self.scope.observed = DISABLED
        settled = successor(old, last_applied=DISABLED)
        self.publish(old, settled)
        self.assertEqual(self.read(), settled)

    def test_unavailable_or_untyped_query_never_publishes(self):
        old = self.create()
        for observed in (None, {"mode": "disabled", "cpu_rate_bp": None}):
            with self.subTest(observed=observed):
                self.scope.observed = observed
                self.assert_rejected(old, successor(old))

    def test_query_failure_is_sanitized_and_preserves_prior_record(self):
        old = self.create()
        with patch.object(self.scope, "query_cpu_control", side_effect=RuntimeError("fixture_private_query_detail")):
            with self.assertRaises(journal_module.TestJournalError) as caught:
                self.publish(old, successor(old))
        self.assertEqual(caught.exception.reason, "manifest_cpu_query_unavailable")
        self.assertNotIn("fixture_private_query_detail", str(caught.exception))
        self.assertEqual(self.read(), old)

    def test_fsync_failure_preserves_old_record_and_removes_owned_temp(self):
        old = self.create()
        before = self.path().read_bytes()
        names = {item.name for item in self.directory.iterdir()}
        with patch.object(journal_module.os, "fsync", side_effect=OSError("fixture_fsync_failure")):
            with self.assertRaises(journal_module.TestJournalError) as caught:
                self.publish(old, successor(old))
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.path().read_bytes(), before)
        self.assertEqual({item.name for item in self.directory.iterdir()}, names)

    def test_scope_is_rechecked_after_fsync_before_publication(self):
        old = self.create()
        real_fsync = journal_module.os.fsync

        def lose_scope(fd):
            real_fsync(fd)
            self.scope.valid = False

        with patch.object(journal_module.os, "fsync", side_effect=lose_scope):
            self.assert_rejected(old, successor(old))

    def test_control_is_requeried_after_fsync_before_publication(self):
        old = self.create()
        real_fsync = journal_module.os.fsync

        def external_change(fd):
            real_fsync(fd)
            self.scope.observed = OTHER_CAP

        with patch.object(journal_module.os, "fsync", side_effect=external_change):
            self.assert_rejected(old, successor(old))
        self.assertGreaterEqual(self.scope.queries, 2)

    def test_replace_success_followed_by_error_is_reconciled_without_duplicate_sequence(self):
        old = self.create()
        candidate = successor(old, root_identity=ROOT)
        real_replace = journal_module.os.replace

        def replace_then_fail(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise OSError("fixture_ack_lost_after_replace")

        with patch.object(journal_module.os, "replace", side_effect=replace_then_fail):
            with self.assertRaises(journal_module.TestJournalError) as caught:
                self.publish(old, candidate)
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), candidate)
        with self.assertRaises(journal_module.TestJournalError):
            self.publish(old, candidate)
        self.assertEqual(self.read(), candidate)
        self.assertEqual(self.read().manifest_seq, old.manifest_seq + 1)

    def test_mock_interrupt_after_replace_keeps_original_exception_and_new_record(self):
        old = self.create()
        candidate = successor(old, root_identity=ROOT)
        real_replace = journal_module.os.replace
        interruption = KeyboardInterrupt("fixture_interruption")

        def replace_then_interrupt(*args, **kwargs):
            real_replace(*args, **kwargs)
            raise interruption

        with patch.object(journal_module.os, "replace", side_effect=replace_then_interrupt):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.publish(old, candidate)
        self.assertIs(caught.exception, interruption)
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), candidate)

    def test_malformed_oversized_or_hash_damaged_targets_are_not_overwritten(self):
        damaged = json.loads(self.base.to_json())
        damaged["manifest_seq"] = 7
        duplicate_key = (self.base.to_json()[:-1] + ',"test_only":true}').encode("utf-8")
        cases = (b"{", b"x" * (MAX_MESSAGE_BYTES + 1),
                 json.dumps(damaged).encode("utf-8"), duplicate_key)
        for payload in cases:
            with self.subTest(length=len(payload)):
                self.path().write_bytes(payload)
                with self.assertRaises(journal_module.TestJournalError):
                    self.read()
                with self.assertRaises(journal_module.TestJournalError):
                    self.publish(self.base, successor(self.base))
                self.assertEqual(self.path().read_bytes(), payload)

    def test_record_for_another_execution_at_expected_filename_is_rejected(self):
        alien = record()
        self.path().write_text(alien.to_json(), encoding="utf-8")
        with self.assertRaises(journal_module.TestJournalError):
            self.read()
        with self.assertRaises(journal_module.TestJournalError):
            self.publish(self.base, successor(self.base))
        self.assertEqual(self.path().read_text(encoding="utf-8"), alien.to_json())

    def test_synthetic_reparse_attributes_reject_target_and_ancestor(self):
        self.create()
        before = self.path().read_bytes()
        real_lstat = journal_module.os.lstat

        class ReparseStat:
            def __init__(self, original):
                self.original = original
                self.st_file_attributes = getattr(original, "st_file_attributes", 0) | 0x400

            def __getattr__(self, name):
                return getattr(self.original, name)

        for unsafe_path in (self.path(), self.directory):
            def reparse_lstat(path, *args, **kwargs):
                observed = real_lstat(path, *args, **kwargs)
                return ReparseStat(observed) if Path(path) == unsafe_path else observed

            with self.subTest(target=unsafe_path.name):
                with patch.object(journal_module.os, "lstat", side_effect=reparse_lstat):
                    with self.assertRaises(journal_module.TestJournalError):
                        self.read()
                    with self.assertRaises(journal_module.TestJournalError):
                        self.publish(self.base, successor(self.base))
                self.assertEqual(self.path().read_bytes(), before)

    def test_directory_replacement_after_fsync_preserves_prior_evidence(self):
        active = self.directory / "records"
        active.mkdir()
        saved = self.directory / "saved-records"
        journal = journal_module.TestRecoveryJournal(active)
        with self.scope.held():
            journal.create(self.base, writer_scope=self.scope)
        original = (active / self.path().name).read_bytes()
        real_fsync = journal_module.os.fsync
        real_assert_held = self.scope.assert_held
        state = {"fsynced": False, "replaced": False}

        def mark_fsynced(fd):
            real_fsync(fd)
            state["fsynced"] = True

        def replace_directory_after_close():
            real_assert_held()
            # The next scope check occurs after the staging stream closes;
            # Windows need not permit renaming a directory with an open file.
            if state["fsynced"] and not state["replaced"]:
                active.rename(saved)
                active.mkdir()
                state["replaced"] = True

        with patch.object(journal_module.os, "fsync", side_effect=mark_fsynced):
            with patch.object(self.scope, "assert_held", side_effect=replace_directory_after_close):
                with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
                    journal.publish(successor(self.base), expected_seq=self.base.manifest_seq,
                                    expected_hash=self.base.manifest_hash, writer_scope=self.scope)
        self.assertTrue(state["replaced"])
        self.assertFalse((active / self.path().name).exists())
        self.assertEqual((saved / self.path().name).read_bytes(), original)

    def test_cleanup_failure_does_not_replace_primary_write_failure(self):
        old = self.create()
        with patch.object(journal_module.os, "fsync", side_effect=OSError("fixture_write_failure")):
            with patch.object(self.journal, "_cleanup_temp", side_effect=RuntimeError("fixture_cleanup_failure")):
                with self.assertRaises(journal_module.TestJournalError) as caught:
                    self.publish(old, successor(old))
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), old)
        self.assertIn("manifest_temporary_cleanup_unverified", getattr(caught.exception, "__notes__", ()))
        self.assertNotIn("fixture_cleanup_failure", str(caught.exception))

    def test_cleanup_failure_after_publication_reports_uncertainty_and_preserves_new_record(self):
        old = self.create()
        candidate = successor(old)
        with patch.object(self.journal, "_cleanup_temp", side_effect=RuntimeError("fixture_cleanup_failure")):
            with self.assertRaises(journal_module.TestJournalError) as caught:
                self.publish(old, candidate)
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), candidate)

    def test_fdopen_failure_closes_newly_opened_descriptor_and_preserves_record(self):
        old = self.create()
        real_open = journal_module.os.open
        real_close = journal_module.os.close
        real_fdopen = journal_module.os.fdopen
        opened, closed = [], []

        def open_record(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        def close_record(descriptor):
            closed.append(descriptor)
            return real_close(descriptor)

        def partially_wrap_then_fail(descriptor, mode, **kwargs):
            self.assertIs(kwargs.get("closefd"), False)
            self.assertEqual(kwargs.get("buffering"), 0)
            stream = real_fdopen(descriptor, mode, **kwargs)
            stream.close()
            # A partially constructed stream must not take ownership of the
            # raw descriptor, which the helper must still close exactly once.
            self.assertGreater(journal_module.os.fstat(descriptor).st_ino, 0)
            raise OSError("fixture_fdopen_failure")

        with patch.object(journal_module.os, "open", side_effect=open_record):
            with patch.object(journal_module.os, "fdopen", side_effect=partially_wrap_then_fail):
                with patch.object(journal_module.os, "close", side_effect=close_record):
                    with self.assertRaises(journal_module.TestJournalError):
                        self.read()
        self.assertEqual(len(opened), 1)
        self.assertEqual(closed, opened)
        self.assertEqual(self.read(), old)

    def test_directory_target_is_rejected_and_preserved(self):
        self.path().mkdir()
        with self.assertRaises(journal_module.TestJournalError):
            self.read()
        with self.scope.held(), self.assertRaises(journal_module.TestJournalError):
            self.journal.create(self.base, writer_scope=self.scope)
        self.assertTrue(self.path().is_dir())

    def test_short_raw_read_cannot_hide_suffix_after_valid_record(self):
        valid = self.base.to_json().encode("utf-8")
        payload = valid + b"fixture-unread-suffix"
        self.path().write_bytes(payload)
        real_fdopen = journal_module.os.fdopen

        class PrefixReader:
            def __init__(self, stream):
                self.stream = stream

            def fileno(self):
                return self.stream.fileno()

            def read(self, size):
                return self.stream.read(size)[:len(valid)]

            def close(self):
                self.stream.close()

        def return_short_reader(*args, **kwargs):
            return PrefixReader(real_fdopen(*args, **kwargs))

        with patch.object(journal_module.os, "fdopen", side_effect=return_short_reader):
            with self.assertRaises(journal_module.TestJournalError):
                self.read()
        self.assertEqual(self.path().read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
