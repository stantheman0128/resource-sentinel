"""Production-schema journal fixtures; no native Job/control or recovery proof."""
from contextlib import contextmanager
from dataclasses import fields
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import recovery_journal as journal_module
from sentinel.adaptive.contracts import (
    AllocationKind, CpuControl, CpuControlMode, MAX_MESSAGE_BYTES, PendingIntent,
    ProcessIdentity, RecoveryManifest, ReservationRef, ResourceDemand,
)


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
CAP = CpuControl(CpuControlMode.HARD_CAP, 2500)
OTHER_CAP = CpuControl(CpuControlMode.HARD_CAP, 4000)
WRAPPER = ProcessIdentity(4101, 134343072000000001, "fixture-logon")
GUARDIAN = ProcessIdentity(4102, 134343072000000002, "fixture-logon")
ROOT = ProcessIdentity(4103, 134343072000000003, "fixture-logon")
FLOOR = ResourceDemand(2.0, 2 << 20, 3 << 20, 1)
ERROR = journal_module.RecoveryJournalError


class HeldScope:
    """Explicit fixture for thread-owned POLICY and Job locks, not OS authority."""

    def __init__(self, item, *, locks=None):
        for name in ("execution_id", "creation_nonce", "job_name", "reservation", "spec_hash"):
            setattr(self, name, getattr(item, name))
        self.locks = (threading.Lock(), threading.Lock()) if locks is None else locks
        self.thread_id = None
        self.valid = True
        self.observed = DISABLED
        self.queries = 0
        self.set_cpu_control = Mock(side_effect=AssertionError("fixture_control_write_forbidden"))

    @contextmanager
    def held(self):
        acquired = []
        try:
            for lock in self.locks:
                if not lock.acquire(timeout=2):
                    raise AssertionError("fixture_mutex_timeout")
                acquired.append(lock)
            self.thread_id = threading.get_ident()
            yield self
        finally:
            self.thread_id = None
            for lock in reversed(acquired):
                lock.release()

    def assert_held(self):
        if (not self.valid or self.thread_id != threading.get_ident() or
                not all(lock.locked() for lock in self.locks)):
            raise RuntimeError("fixture_scope_not_held")

    def query_cpu_control(self):
        self.assert_held()
        self.queries += 1
        return self.observed


def record():
    execution, nonce = str(uuid4()), uuid4().hex
    return RecoveryManifest.create(
        execution_id=execution,
        reservation=ReservationRef(AllocationKind.DIRECT, "fixture-reservation"),
        spec_hash="a" * 64,
        job_name=f"Local\\ResourceSentinel.Job.{execution}.{nonce}",
        creation_nonce=nonce, wrapper_identity=WRAPPER, root_identity=None,
        guardian_identity=GUARDIAN, guardian_epoch="fixture-epoch", original=DISABLED,
        last_applied=None, pending_intent=None, allocated_floor=FLOOR, manifest_seq=0,
    )


def successor(old, **changes):
    values = {field.name: getattr(old, field.name) for field in fields(old)
              if field.name != "manifest_hash"}
    values["manifest_seq"] = old.manifest_seq + 1
    values.update(changes)
    return RecoveryManifest.create(**values)


def portable_publish(temporary, target, *, replace):
    """Explicit filesystem fixture, never substituted for the native default."""
    if replace:
        os.replace(temporary, target)
    else:
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as error:
            # This exact exclusive syscall positively refused the target.
            error._journal_exclusive_collision = True
            raise


def checksummed(payload):
    payload = dict(payload)
    payload.pop("manifest_hash", None)
    encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    payload["manifest_hash"] = hashlib.sha256(encoded).hexdigest()
    return json.dumps(payload).encode("utf-8")


class ProductionRecoveryJournalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-production-journal-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.journal = journal_module.RecoveryJournal(self.directory, publisher=portable_publish)
        self.base = record()
        self.scope = HeldScope(self.base)
        self.path = self.directory / (self.base.execution_id + ".json")

    def read(self):
        return self.journal.read(self.base.execution_id, creation_nonce=self.base.creation_nonce)

    def create(self):
        with self.scope.held():
            self.assertEqual(self.journal.create(self.base, writer_scope=self.scope), self.base)
        return self.base

    def publish(self, old, candidate, scope=None):
        scope = self.scope if scope is None else scope
        with scope.held():
            return self.journal.publish(candidate, expected_seq=old.manifest_seq,
                                        expected_hash=old.manifest_hash, writer_scope=scope)

    def reject(self, old, candidate, scope=None):
        before = self.path.read_bytes()
        with self.assertRaises(ERROR):
            self.publish(old, candidate, scope)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.read(), old)

    def pending(self):
        old = self.create()
        pending = successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP))
        self.publish(old, pending)
        return pending

    def test_create_roundtrips_formal_schema_without_query_or_fixture_markers(self):
        self.scope.observed = OTHER_CAP  # Pre-Job creation cannot query a future Job.
        self.create()
        self.assertEqual(self.read(), self.base)
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(RecoveryManifest.from_dict(payload), self.base)
        self.assertEqual(payload["reservation"], self.base.reservation.to_dict())
        self.assertEqual(payload["spec_hash"], self.base.spec_hash)
        self.assertNotIn("test_only", payload)
        self.assertNotIn("fixture_schema_version", payload)
        self.assertEqual(self.scope.queries, 0)
        self.scope.set_cpu_control.assert_not_called()

    def test_create_rejects_noninitial_state_and_untyped_payload(self):
        for changes in ({"manifest_seq": 1}, {"root_identity": ROOT},
                        {"last_applied": DISABLED},
                        {"pending_intent": PendingIntent(str(uuid4()), DISABLED, CAP)}):
            values = {"manifest_seq": 0, **changes}
            with self.subTest(fields=tuple(changes)), self.scope.held(), self.assertRaises(ERROR):
                self.journal.create(successor(self.base, **values), writer_scope=self.scope)
        with self.scope.held(), self.assertRaises(ERROR):
            self.journal.create(self.base.to_dict(), writer_scope=self.scope)
        self.assertFalse(self.path.exists())

    def test_scope_requires_all_bindings_and_current_thread_ownership(self):
        with self.assertRaises(ERROR):
            self.journal.create(self.base, writer_scope=self.scope)
        mismatches = dict(execution_id=str(uuid4()), creation_nonce=uuid4().hex,
                          job_name="Local\\ResourceSentinel.Job.unowned",
                          reservation=ReservationRef(AllocationKind.ROUTED, "other"),
                          spec_hash="b" * 64)
        for name, value in mismatches.items():
            scope = HeldScope(self.base)
            setattr(scope, name, value)
            with self.subTest(field=name), scope.held(), self.assertRaises(ERROR):
                self.journal.create(self.base, writer_scope=scope)
        errors = []
        def borrower():
            try:
                self.journal.create(self.base, writer_scope=self.scope)
            except Exception as error:
                errors.append(error)
        with self.scope.held():
            worker = threading.Thread(target=borrower)
            worker.start()
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], ERROR)
        self.assertFalse(self.path.exists())

    def test_initial_publication_collision_never_overwrites_existing_bytes(self):
        original = b"unknown-existing-evidence"
        real_publish = self.journal._publisher
        def collision(temporary, target, *, replace):
            self.assertFalse(replace)
            Path(target).write_bytes(original)
            return real_publish(temporary, target, replace=replace)
        with patch.object(self.journal, "_publisher", side_effect=collision):
            with self.scope.held(), self.assertRaises(ERROR) as caught:
                self.journal.create(self.base, writer_scope=self.scope)
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.path.read_bytes(), original)

    def test_exact_cas_and_one_step_increment_are_required(self):
        old = self.create()
        for sequence, digest in ((True, old.manifest_hash), (1, old.manifest_hash),
                                 (0, "f" * 64), (0, "invalid")):
            with self.subTest(sequence=sequence), self.scope.held(), self.assertRaises(ERROR):
                self.journal.publish(successor(old), expected_seq=sequence,
                                     expected_hash=digest, writer_scope=self.scope)
            self.assertEqual(self.read(), old)
        for sequence in (0, 2):
            self.reject(old, successor(old, manifest_seq=sequence))

    def test_bound_reservation_spec_and_creation_provenance_are_immutable(self):
        old = self.create()
        changes = ({"reservation": ReservationRef(AllocationKind.ROUTED, "other")},
                   {"spec_hash": "b" * 64}, {"guardian_epoch": "other-epoch"},
                   {"wrapper_identity": ROOT}, {"guardian_identity": ROOT})
        for change in changes:
            candidate = successor(old, **change)
            with self.subTest(fields=tuple(change)):
                # Matching the new scope must not conceal mutation of stored binding.
                self.reject(old, candidate, HeldScope(candidate))

    def test_root_binds_once_and_every_allocated_floor_dimension_is_monotonic(self):
        old = self.create()
        larger = ResourceDemand(3.0, 3 << 20, 4 << 20, 2)
        bound = successor(old, root_identity=ROOT, allocated_floor=larger)
        self.publish(old, bound)
        for root in (None, ProcessIdentity(ROOT.pid, ROOT.created_filetime_100ns + 1, ROOT.logon_id)):
            self.reject(bound, successor(bound, root_identity=root))
        for name in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            values = larger.to_dict()
            values[name] -= 1
            with self.subTest(dimension=name):
                self.reject(bound, successor(bound, allocated_floor=ResourceDemand(**values)))

    def test_two_concurrent_writers_with_one_revision_have_one_cas_winner(self):
        old = self.create()
        candidates = [successor(old, allocated_floor=ResourceDemand(cpu, 2 << 20, 3 << 20, 1))
                      for cpu in (3.0, 4.0)]
        barrier, outcomes = threading.Barrier(3), []
        def writer(candidate):
            try:
                barrier.wait(timeout=3)
                self.publish(old, candidate, HeldScope(old, locks=self.scope.locks))
                outcomes.append(candidate)
            except Exception as error:
                outcomes.append(error)
        workers = [threading.Thread(target=writer, args=(candidate,)) for candidate in candidates]
        for worker in workers:
            worker.start()
        barrier.wait(timeout=3)
        for worker in workers:
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
        successes = [value for value in outcomes if isinstance(value, RecoveryManifest)]
        failures = [value for value in outcomes if isinstance(value, ERROR)]
        self.assertEqual(len(successes), 1, outcomes)
        self.assertEqual(len(failures), 1, outcomes)
        self.assertEqual(self.read(), successes[0])

    def test_intent_observed_apply_and_restore_are_evidence_without_control_writes(self):
        pending = self.pending()
        self.scope.observed = CAP
        applied = successor(pending, pending_intent=None, last_applied=CAP)
        self.publish(pending, applied)
        self.scope.observed = DISABLED
        restored = successor(applied, last_applied=DISABLED)
        self.publish(applied, restored)
        self.assertEqual(self.read(), restored)
        self.assertGreaterEqual(self.scope.queries, 6)
        self.scope.set_cpu_control.assert_not_called()

    def test_cap_requires_intent_and_new_intent_requires_current_old_control(self):
        old = self.create()
        self.scope.observed = CAP
        self.reject(old, successor(old, last_applied=CAP))
        self.reject(old, successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP)))
        self.scope.observed = DISABLED
        self.reject(old, successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, DISABLED)))

    def test_pending_cannot_be_replaced_or_settled_against_current_query(self):
        pending = self.pending()
        self.reject(pending, successor(pending, pending_intent=PendingIntent(str(uuid4()), DISABLED, OTHER_CAP)))
        self.reject(pending, successor(pending, pending_intent=None, last_applied=CAP))
        self.scope.observed = OTHER_CAP
        self.reject(pending, successor(pending, pending_intent=None, last_applied=OTHER_CAP))
        self.reject(pending, successor(pending, root_identity=ROOT))
        self.scope.observed = DISABLED
        settled = successor(pending, pending_intent=None, last_applied=DISABLED)
        self.publish(pending, settled)
        self.assertEqual(self.read(), settled)

    def test_untyped_and_failed_queries_are_sanitized_and_preserve_record(self):
        old = self.create()
        for observed in (None, {"mode": "disabled", "cpu_rate_bp": None}):
            self.scope.observed = observed
            self.reject(old, successor(old))
        with patch.object(self.scope, "query_cpu_control", side_effect=RuntimeError("private-query-value")):
            with self.assertRaises(ERROR) as caught:
                self.publish(old, successor(old))
        self.assertNotIn("private-query-value", str(caught.exception))
        self.assertEqual(self.read(), old)

    def test_fsync_failure_prevents_first_or_replacement_publication(self):
        with patch.object(journal_module.os, "fsync", side_effect=OSError("private-storage-value")):
            with self.scope.held(), self.assertRaises(ERROR) as caught:
                self.journal.create(self.base, writer_scope=self.scope)
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertEqual(list(self.directory.iterdir()), [])
        old = self.create()
        with patch.object(journal_module.os, "fsync", side_effect=OSError("private-storage-value")):
            with self.assertRaises(ERROR) as caught:
                self.publish(old, successor(old))
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertNotIn("private-storage-value", str(caught.exception))
        self.assertEqual(self.read(), old)
        self.assertEqual(list(self.directory.iterdir()), [self.path])

    def test_scope_and_actual_control_are_rechecked_after_fsync(self):
        old = self.create()
        real_fsync = journal_module.os.fsync
        for change in ("scope", "control"):
            def changed_after_flush(fd):
                real_fsync(fd)
                if change == "scope":
                    self.scope.valid = False
                else:
                    self.scope.observed = OTHER_CAP
            self.scope.valid, self.scope.observed = True, DISABLED
            with self.subTest(change=change), patch.object(journal_module.os, "fsync", side_effect=changed_after_flush):
                self.reject(old, successor(old, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP)))
        self.assertGreaterEqual(self.scope.queries, 3)

    def test_revision_changed_during_fsync_preserves_winner(self):
        old = self.create()
        winner = successor(old, root_identity=ROOT)
        real_fsync = journal_module.os.fsync
        def changed_after_flush(fd):
            real_fsync(fd)
            self.path.write_text(winner.to_json(), encoding="utf-8")
        with patch.object(journal_module.os, "fsync", side_effect=changed_after_flush):
            with self.assertRaises(ERROR) as caught:
                self.publish(old, successor(old))
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), winner)

    def test_settlement_rechecks_query_after_fsync_and_keeps_pending_evidence(self):
        pending = self.pending()
        settled = successor(pending, pending_intent=None, last_applied=CAP)
        real_fsync = journal_module.os.fsync
        for changed in (OTHER_CAP, None):
            self.scope.observed = CAP
            def changed_after_flush(fd):
                real_fsync(fd)
                self.scope.observed = changed
            with patch.object(journal_module.os, "fsync", side_effect=changed_after_flush):
                self.reject(pending, settled)

    def test_successful_publication_with_lost_ack_is_unknown_and_cannot_replay(self):
        old = self.create()
        real_publish = self.journal._publisher
        for kind in (OSError, FileExistsError):
            candidate = successor(old, pending_intent=old.pending_intent or
                                  PendingIntent(str(uuid4()), DISABLED, CAP))
            set_after_success = Mock()
            def publish_then_fail(*args, **kwargs):
                real_publish(*args, **kwargs)
                raise kind("private-ack-lost")
            with self.subTest(exception=kind.__name__):
                with patch.object(self.journal, "_publisher", side_effect=publish_then_fail) as publisher:
                    with self.assertRaises(ERROR) as caught:
                        self.publish(old, candidate)
                        set_after_success(CAP)  # Consumer advances only after normal return.
                publisher.assert_called_once()
                self.assertTrue(caught.exception.publication_may_have_occurred)
                set_after_success.assert_not_called()
                self.scope.set_cpu_control.assert_not_called()
                self.assertEqual(self.read(), candidate)
                with self.assertRaises(ERROR):
                    self.publish(old, candidate)
                self.assertEqual(self.read(), candidate)
            old = candidate

    def test_postpublication_readback_failure_retains_new_evidence_and_uncertainty(self):
        old = self.create()
        candidate = successor(old, root_identity=ROOT)
        real_publish, real_read = self.journal._publisher, self.journal.read
        published = False
        def publish(*args, **kwargs):
            nonlocal published
            result = real_publish(*args, **kwargs)
            published = True
            return result
        def read(*args, **kwargs):
            if published:
                raise ERROR("manifest_read_unavailable")
            return real_read(*args, **kwargs)
        with patch.object(self.journal, "_publisher", side_effect=publish):
            with patch.object(self.journal, "read", side_effect=read), self.assertRaises(ERROR) as caught:
                self.publish(old, candidate)
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), candidate)

    def test_publisher_returning_false_cannot_report_success(self):
        old = self.create()
        with patch.object(self.journal, "_publisher", return_value=False):
            with self.assertRaises(ERROR) as caught:
                self.publish(old, successor(old))
        self.assertTrue(caught.exception.publication_may_have_occurred)
        self.assertEqual(self.read(), old)

    def test_read_close_unknown_preserves_owner_without_retry_or_private_error(self):
        old = self.create()
        real_close, closed = journal_module.os.close, []
        def close_then_fail(descriptor):
            real_close(descriptor)
            closed.append(descriptor)
            raise OSError("private-close-outcome")
        with patch.object(journal_module.os, "close", side_effect=close_then_fail):
            with self.assertRaises(ERROR) as caught:
                self.read()
        self.assertEqual(len(closed), 1)
        self.assertEqual(caught.exception._journal_cleanup_owner, closed[0])
        self.assertNotIn("private-close-outcome", str(caught.exception))
        self.assertEqual(self.read(), old)

    def test_failed_write_and_unknown_close_keep_owner_and_only_safe_note(self):
        old = self.create()
        real_open, real_close = journal_module.os.open, journal_module.os.close
        writing, closed = [], []
        def open_file(path, flags, *args, **kwargs):
            descriptor = real_open(path, flags, *args, **kwargs)
            if flags & os.O_WRONLY:
                writing.append(descriptor)
            return descriptor
        def close_file(descriptor):
            real_close(descriptor)
            if writing and descriptor == writing[-1]:
                closed.append(descriptor)
                raise OSError("private-cleanup-detail")
        with patch.object(journal_module.os, "open", side_effect=open_file):
            with patch.object(journal_module.os, "close", side_effect=close_file):
                with patch.object(journal_module.os, "fsync", side_effect=OSError("private-write-detail")):
                    with self.assertRaises(ERROR) as caught:
                        self.publish(old, successor(old))
        self.assertEqual(len(writing), 1)
        self.assertEqual(closed, writing)
        self.assertEqual(caught.exception._journal_cleanup_owner, writing[0])
        self.assertEqual(caught.exception.__notes__, ["manifest_stream_cleanup_unverified"])
        self.assertFalse(caught.exception.publication_may_have_occurred)
        self.assertNotIn("private-", str(caught.exception))
        self.assertEqual(self.read(), old)

    def test_private_raw_payload_and_fixture_markers_are_rejected_with_valid_checksum(self):
        for field in ("command", "raw_command", "cwd", "env", "test_only", "fixture_schema_version"):
            payload = self.base.to_dict()
            payload[field] = "private-fixture-value"
            encoded = checksummed(payload)
            self.path.write_bytes(encoded)
            with self.subTest(field=field), self.assertRaises(ERROR) as caught:
                self.read()
            self.assertNotIn("private-fixture-value", str(caught.exception))
            with self.assertRaises(ERROR):
                self.publish(self.base, successor(self.base))
            self.assertEqual(self.path.read_bytes(), encoded)

    def test_malformed_oversized_duplicate_and_hash_damaged_files_are_preserved(self):
        damaged = self.base.to_dict()
        damaged["manifest_seq"] += 1
        duplicate = self.base.to_json()[:-1] + ',"manifest_seq":0}'
        for encoded in (b"{", b"x" * (MAX_MESSAGE_BYTES + 1), duplicate.encode(),
                        json.dumps(damaged).encode()):
            self.path.write_bytes(encoded)
            with self.subTest(length=len(encoded)), self.assertRaises(ERROR):
                self.read()
            with self.assertRaises(ERROR):
                self.publish(self.base, successor(self.base))
            self.assertEqual(self.path.read_bytes(), encoded)

    def test_path_nonce_and_foreign_execution_are_rejected_without_modification(self):
        self.create()
        for execution, nonce in (("../escape", self.base.creation_nonce),
                                 (self.base.execution_id, "bad-nonce"),
                                 (self.base.execution_id, uuid4().hex)):
            with self.assertRaises(ERROR):
                self.journal.read(execution, creation_nonce=nonce)
        self.assertEqual(self.read(), self.base)
        for directory in (Path("relative-fixture"), self.directory / "missing", self.directory / ".."):
            with self.assertRaises(ERROR):
                journal_module.RecoveryJournal(directory)
        alien = record().to_json().encode()
        self.path.write_bytes(alien)
        with self.assertRaises(ERROR):
            self.read()
        with self.assertRaises(ERROR):
            self.publish(self.base, successor(self.base))
        self.assertEqual(self.path.read_bytes(), alien)

    def test_reparse_target_or_ancestor_cannot_be_read_or_replaced(self):
        old = self.create()
        real_lstat = journal_module.os.lstat
        class ReparseStat:
            def __init__(self, value):
                self.value = value
                self.st_file_attributes = getattr(value, "st_file_attributes", 0) | 0x400
            def __getattr__(self, name):
                return getattr(self.value, name)
        for unsafe in (self.path, self.directory):
            def lstat(path, *args, **kwargs):
                value = real_lstat(path, *args, **kwargs)
                return ReparseStat(value) if Path(path) == unsafe else value
            with patch.object(journal_module.os, "lstat", side_effect=lstat):
                with self.assertRaises(ERROR):
                    self.read()
                with self.assertRaises(ERROR):
                    self.publish(old, successor(old))
            self.assertEqual(self.read(), old)


class NativePublicationAbiTests(unittest.TestCase):
    """Mocked ABI only; no loaded DLL, native publication, or capability pass."""

    def test_windows_abi_uses_write_through_without_cross_volume_copy(self):
        function = Mock(return_value=1)
        journal_module._move_file.cache_clear()
        self.addCleanup(journal_module._move_file.cache_clear)
        paths = (r"C:\fixture\staged.tmp", r"C:\fixture\execution.json")
        with patch.object(journal_module.C, "WinDLL", create=True,
                          return_value=Mock(MoveFileExW=function)) as load:
            with patch.object(journal_module.os, "name", "nt"):
                self.assertIsNone(journal_module._publish_namespace(*paths, replace=False))
                self.assertIsNone(journal_module._publish_namespace(*paths, replace=True))
        load.assert_called_once_with("kernel32", use_last_error=True)
        self.assertEqual(function.restype, journal_module.C.c_int32)
        self.assertEqual(function.argtypes,
                         (journal_module.C.c_wchar_p, journal_module.C.c_wchar_p, journal_module.C.c_uint32))
        self.assertEqual([call.args for call in function.call_args_list],
                         [(*paths, 0x8), (*paths, 0x9)])

    def test_windows_failed_or_malformed_bool_has_no_publication_fallback(self):
        paths = (r"C:\fixture\staged.tmp", r"C:\fixture\execution.json")
        with patch.object(journal_module.os, "replace") as replace, patch.object(journal_module.os, "link") as link:
            with patch.object(journal_module.C, "get_last_error", return_value=5, create=True):
                for result, exception in ((0, OSError), (None, ERROR), (True, ERROR)):
                    with self.subTest(result=result), patch.object(journal_module, "_move_file", return_value=Mock(return_value=result)):
                        with patch.object(journal_module.os, "name", "nt"), self.assertRaises(exception):
                            journal_module._publish_namespace(*paths, replace=True)
            with patch.object(journal_module.C, "get_last_error", return_value=183, create=True):
                with patch.object(journal_module, "_move_file", return_value=Mock(return_value=0)):
                    with patch.object(journal_module.os, "name", "nt"), self.assertRaises(FileExistsError) as caught:
                        journal_module._publish_namespace(*paths, replace=False)
            self.assertTrue(caught.exception._journal_exclusive_collision)
            replace.assert_not_called()
            link.assert_not_called()


if __name__ == "__main__":
    unittest.main()
