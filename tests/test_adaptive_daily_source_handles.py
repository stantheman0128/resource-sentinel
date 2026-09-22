"""Synthetic source custody tests; no native filesystem mutations."""
from dataclasses import replace
import hashlib
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts.daily_source_handles import (
    FileSnapshot, NativeFileIdentity, NativeSourceFiles, SourceFileError,
    _StatDuplicate, _WindowsBackend,
)


TARGET = r"C:\repo\source.py"
NEW = r"C:\repo\new.py"
OLD = b"original source\n"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Backend:
    def __init__(self):
        self.nodes, self.handles = {}, {}
        self.opened, self.calls, self.closed = [], [], []
        self.created = []
        self.failure = None
        self.corrupt_readback = False
        self._next = 100
        self.add("C:\\", directory=True)
        self.add(r"C:\repo", directory=True)
        self.add(TARGET, data=OLD)

    def add(self, path, *, directory=False, data=b"", attributes=None):
        index = len(self.nodes) + 1
        identity = NativeFileIdentity(7, index, 9007, f"{index:032x}")
        self.nodes[path] = {"data": data, "identity": identity,
                           "attributes": (0x10 if directory else 0x20) if attributes is None else attributes,
                           "directory": directory, "path": path, "links": 1,
                           "delete_pending": False, "mtime_ns": 123456789, "closed": False}

    def check(self, operation):
        if self.failure == operation:
            raise RuntimeError("synthetic native interruption")

    def open(self, path, *, directory, new):
        self.opened.append((path, directory, new))
        self.check("open")
        if new:
            if path in self.nodes:
                raise SourceFileError("source_open_failed", known_failed=True, win32_error=80)
            self.add(path)
        if path not in self.nodes:
            raise SourceFileError("source_open_failed", known_failed=True, win32_error=2)
        self._next += 1
        self.handles[self._next] = self.nodes[path]
        return self._next

    def create_directory(self, path):
        self.calls.append(("create_directory", path))
        if path in self.nodes:
            return False
        self.add(path, directory=True)
        self.created.append(path)
        self.check("create_directory")
        return True

    def snapshot(self, handle):
        self.check("snapshot")
        node = self.handles[handle]
        return FileSnapshot(node["identity"], node["path"], len(node["data"]),
                            node["attributes"], node["links"], node["delete_pending"])

    def stat_identity(self, handle):
        self.check("stat_identity")
        node = self.handles[handle]
        # Intentionally differs from raw Win32 identity representation.
        return {"device": 7007, "file_id": node["identity"].file_index64 + 10000,
                "size": len(node["data"]), "mtime_ns": node["mtime_ns"]}

    def read(self, handle, max_bytes):
        self.check("read")
        result = self.handles[handle]["data"]
        return result + b"bad" if self.corrupt_readback else result

    def write(self, handle, data):
        self.calls.append(("write", handle))
        node = self.handles[handle]
        node["data"] = data + node["data"][len(data):]
        self.check("write")

    def truncate(self, handle, size):
        self.calls.append(("truncate", handle))
        self.handles[handle]["data"] = self.handles[handle]["data"][:size]
        self.check("truncate")

    def flush(self, handle):
        self.calls.append(("flush", handle))
        self.check("flush")

    def delete(self, handle):
        self.calls.append(("delete", handle))
        self.handles[handle]["delete_pending"] = True
        self.check("delete")

    def close(self, handle):
        self.calls.append(("close", handle))
        if self.failure == "close_known":
            raise SourceFileError("source_close_failed", known_failed=True)
        self.check("close")
        self.closed.append(handle)
        self.handles[handle]["closed"] = True


class SourceHandleTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.files = NativeSourceFiles(backend=self.backend)

    def open(self, **kwargs):
        owner = self.files.open_existing(TARGET, **kwargs)
        self.addCleanup(owner.close)
        return owner

    def acquire_error(self, reason, **kwargs):
        with self.assertRaisesRegex(SourceFileError, reason) as error:
            self.files.open_existing(TARGET, **kwargs)
        owner = error.exception.retained_file
        self.assertIsNotNone(owner)
        self.assertTrue(owner.quarantined)
        self.addCleanup(owner.close)
        return owner

    def test_existing_acquisition_only_reads_and_keeps_exact_backup(self):
        owner = self.open(expected_sha256=digest(OLD))
        self.assertEqual(owner.backup_bytes, OLD)
        self.assertEqual(owner.sha256, digest(OLD))
        self.assertEqual(owner.normalized_path, TARGET)
        self.assertEqual(owner.native_identity, self.backend.nodes[TARGET]["identity"])
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.opened,
            [("C:\\", True, False), (r"C:\repo", True, False), (TARGET, False, False)])

    def test_stat_identity_is_exact_separate_representation_and_copy(self):
        owner = self.open()
        self.assertEqual(owner.stat_identity, {"device": 7007, "file_id": 10003,
                                              "size": len(OLD), "mtime_ns": 123456789})
        self.assertNotEqual(owner.stat_identity["device"], owner.native_identity.volume_serial_number32)
        value = owner.stat_identity
        value["device"] = 0
        self.assertEqual(owner.stat_identity["device"], 7007)

    def test_write_truncates_flushes_reads_same_handle_and_preserves_backup(self):
        owner = self.open()
        opens = list(self.backend.opened)
        owner.overwrite(b"new", expected_sha256=digest(OLD))
        self.assertEqual(self.backend.calls, [("write", 103), ("truncate", 103), ("flush", 103)])
        self.assertEqual(owner.read_bytes(), b"new")
        self.assertEqual(owner.sha256, digest(b"new"))
        self.assertEqual(owner.backup_bytes, OLD)
        self.assertEqual(self.backend.opened, opens)

    def test_explicit_zero_length_write_is_verified(self):
        owner = self.open()
        owner.overwrite(b"", expected_sha256=digest(OLD))
        self.assertEqual(owner.read_bytes(), b"")

    def test_wrong_hash_never_enters_mutating_api(self):
        owner = self.open()
        with self.assertRaisesRegex(SourceFileError, "expected_hash_mismatch"):
            owner.overwrite(b"new", expected_sha256=digest(b"other"))
        self.assertEqual(self.backend.calls, [])
        self.assertFalse(owner.quarantined)

    def test_exact_native_baseline_mismatch_preserves_held_object(self):
        expected = replace(self.backend.nodes[TARGET]["identity"], file_index64=999)
        owner = self.acquire_error("baseline_identity_changed", expected_identity=expected)
        self.assertEqual(self.backend.closed, [])
        self.assertEqual(owner.backup_bytes, OLD)

    def test_baseline_hash_mismatch_does_not_close_or_change_original(self):
        self.acquire_error("baseline_hash_changed", expected_sha256=digest(b"other"))
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.nodes[TARGET]["data"], OLD)

    def test_parent_reparse_is_refused_before_leaf_is_opened(self):
        self.backend.nodes[r"C:\repo"]["attributes"] |= 0x400
        self.acquire_error("path_or_metadata_unverified")
        self.assertEqual(len(self.backend.opened), 2)

    def test_leaf_reparse_hardlink_and_directory_are_refused(self):
        for changed in ({"attributes": 0x420}, {"links": 2}, {"attributes": 0x10}):
            with self.subTest(changed=changed):
                self.backend = Backend()
                self.files = NativeSourceFiles(backend=self.backend)
                self.backend.nodes[TARGET].update(changed)
                self.acquire_error("path_or_metadata_unverified")

    def test_path_and_identity_changes_through_retained_handle_refuse_write(self):
        for change in ("path", "identity"):
            with self.subTest(change=change):
                self.backend = Backend()
                self.files = NativeSourceFiles(backend=self.backend)
                owner = self.open()
                if change == "path":
                    self.backend.nodes[TARGET]["path"] = NEW
                else:
                    self.backend.nodes[TARGET]["identity"] = replace(owner.identity, file_index64=900)
                with self.assertRaises(SourceFileError):
                    owner.overwrite(b"new", expected_sha256=digest(OLD))
                self.assertEqual(self.backend.calls, [])

    def test_write_truncate_and_flush_uncertainty_quarantines_without_retry(self):
        for failure in ("write", "truncate", "flush"):
            with self.subTest(failure=failure):
                self.backend = Backend()
                self.files = NativeSourceFiles(backend=self.backend)
                owner = self.open()
                self.backend.failure = failure
                with self.assertRaisesRegex(SourceFileError, "write_outcome_unknown"):
                    owner.overwrite(b"new", expected_sha256=digest(OLD))
                self.assertTrue(owner.quarantined)
                calls = list(self.backend.calls)
                self.backend.failure = None
                with self.assertRaisesRegex(SourceFileError, "mutation_quarantined"):
                    owner.overwrite(OLD, expected_sha256=digest(b"new"))
                self.assertEqual(self.backend.calls, calls)
                self.assertEqual(owner.sha256, digest(OLD))

    def test_readback_corruption_does_not_clear_quarantine(self):
        owner = self.open()
        original = self.backend.flush
        def flush_then_corrupt(handle):
            original(handle)
            self.backend.corrupt_readback = True
        self.backend.flush = flush_then_corrupt
        with self.assertRaisesRegex(SourceFileError, "source_read_incomplete"):
            owner.overwrite(b"new", expected_sha256=digest(OLD))
        self.assertTrue(owner.quarantined)

    def test_new_file_cannot_replace_existing_path(self):
        with self.assertRaisesRegex(SourceFileError, "source_open_failed") as error:
            self.files.create_new(TARGET)
        self.addCleanup(error.exception.retained_file.close)
        self.assertEqual(self.backend.nodes[TARGET]["data"], OLD)
        self.assertEqual(self.backend.calls, [])

    def test_new_file_delete_requires_exact_bytes_and_same_handle(self):
        owner = self.files.create_new(NEW)
        self.addCleanup(owner.close)
        owner.overwrite(b"new", expected_sha256=digest(b""))
        with self.assertRaisesRegex(SourceFileError, "expected_hash_mismatch"):
            owner.delete_new(expected_sha256=digest(OLD))
        opens = list(self.backend.opened)
        owner.delete_new(expected_sha256=digest(b"new"))
        self.assertTrue(owner.delete_pending)
        self.assertIn(("delete", 103), self.backend.calls)
        self.assertEqual(self.backend.opened, opens)
        with self.assertRaisesRegex(SourceFileError, "deletion_pending"):
            owner.read_bytes()
        owner.close()
        self.assertTrue(owner.closed)
        # Pending is not claimed to be observed directory-entry removal.
        self.assertTrue(owner.delete_pending)

    def test_existing_file_has_no_delete_route(self):
        owner = self.open()
        with self.assertRaisesRegex(SourceFileError, "existing_delete_forbidden"):
            owner.delete_new(expected_sha256=digest(OLD))
        self.assertEqual(self.backend.calls, [])

    def test_uncertain_delete_cannot_be_replayed(self):
        owner = self.files.create_new(NEW)
        self.addCleanup(owner.close)
        self.backend.failure = "delete"
        with self.assertRaisesRegex(SourceFileError, "delete_outcome_unknown"):
            owner.delete_new(expected_sha256=digest(b""))
        self.backend.failure = None
        with self.assertRaisesRegex(SourceFileError, "mutation_quarantined"):
            owner.delete_new(expected_sha256=digest(b""))
        self.assertEqual(self.backend.calls.count(("delete", 103)), 1)

    def test_close_leaf_then_inner_to_outer_parents_is_idempotent(self):
        owner = self.open()
        owner.close()
        owner.close()
        self.assertEqual(self.backend.closed, [103, 102, 101])
        with self.assertRaisesRegex(SourceFileError, "closed_or_closing"):
            owner.read_bytes()

    def test_known_failed_close_retains_all_parents_until_retry(self):
        owner = self.open()
        self.backend.failure = "close_known"
        with self.assertRaisesRegex(SourceFileError, "source_close_failed"):
            owner.close()
        self.assertEqual(self.backend.closed, [])
        self.backend.failure = None
        owner.close()
        self.assertEqual(self.backend.closed, [103, 102, 101])

    def test_uncertain_close_never_reuses_numeric_handle_or_releases_parents(self):
        owner = self.files.open_existing(TARGET)
        self.backend.failure = "close"
        with self.assertRaisesRegex(SourceFileError, "close_outcome_unknown"):
            owner.close()
        calls = list(self.backend.calls)
        self.backend.failure = None
        for _ in range(5):
            with self.assertRaisesRegex(SourceFileError, "handle_outcome_unknown"):
                owner.close()
        self.assertEqual(self.backend.calls, calls)
        self.assertEqual(self.backend.closed, [])

    def test_unknown_open_retains_unresolved_parent_owner(self):
        self.backend.failure = "open"
        with self.assertRaisesRegex(SourceFileError, "acquisition_unverified") as error:
            self.files.open_existing(TARGET)
        owner = error.exception.retained_file
        self.backend.failure = None
        with self.assertRaisesRegex(SourceFileError, "handle_outcome_unknown"):
            owner.close()
        self.assertEqual(self.backend.closed, [])

    def test_auxiliary_stat_custody_blocks_original_and_parent_cleanup(self):
        custody = SimpleNamespace(unresolved=True)
        def close_custody():
            if custody.unresolved:
                raise SourceFileError("source_stat_custody_unknown")
        custody.close = close_custody
        def failed_stat(handle):
            error = SourceFileError("source_stat_unverified")
            error._source_stat_custody = (custody,)
            raise error
        self.backend.stat_identity = failed_stat
        with self.assertRaisesRegex(SourceFileError, "source_stat_unverified") as error:
            self.files.open_existing(TARGET)
        owner = error.exception.retained_file
        with self.assertRaisesRegex(SourceFileError, "stat_custody_unknown"):
            owner.close()
        self.assertEqual(self.backend.closed, [])
        custody.unresolved = False  # synthetic known unresolved cleanup resolved
        owner.close()
        self.assertEqual(self.backend.closed, [103, 102, 101])

    def test_size_bounds_apply_to_initial_and_new_content(self):
        self.files = NativeSourceFiles(backend=self.backend, max_bytes=2)
        self.acquire_error("byte_bound_exceeded")
        self.files = NativeSourceFiles(backend=self.backend, max_bytes=len(OLD))
        owner = self.open()
        with self.assertRaises(ValueError):
            owner.overwrite(OLD + b"x", expected_sha256=digest(OLD))
        self.assertEqual(self.backend.calls, [])

    def test_device_unc_relative_ads_dot_and_deep_paths_are_rejected_before_native(self):
        for path in (r"\\server\share\file.py", r"\\?\C:\source.py", r"C:source.py",
                     r"C:\repo\..\source.py", r"C:\repo\source.py:stream", r"C:\repo\NUL",
                     "C:\\repo\\source.py ", "C:\\" + "a\\" * 128 + "file.py"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.files.open_existing(path)
        self.assertEqual(self.backend.opened, [])

    def test_synthetic_backend_never_loads_native_libraries(self):
        with patch("scripts.daily_source_handles._WindowsBackend",
                   side_effect=AssertionError("native backend must remain unloaded")):
            owner = self.open()
        self.assertEqual(owner.read_bytes(), OLD)


class DuplicateBoundaryTests(unittest.TestCase):
    """Exercise actual duplicate custody logic against synthetic Win32/CRT."""

    def setUp(self):
        self.duplicates, self.fd_closed, self.native_closed, self.transfers = [], [], [], []
        self.native = object.__new__(_WindowsBackend)
        def duplicate(source, original, target, output, rights, inherit, options):
            self.duplicates.append((original, rights, inherit, options))
            output._obj.value = 700
            return True
        self.native.k = SimpleNamespace(GetCurrentProcess=lambda: -1, DuplicateHandle=duplicate)
        self.native.close = lambda handle: self.native_closed.append(handle)
        def transfer(handle, flags):
            self.transfers.append(handle)
            return 30
        self.crt = SimpleNamespace(open_osfhandle=transfer)
        self.crt_patch = patch.dict(sys.modules, {"msvcrt": self.crt})
        self.crt_patch.start()
        self.addCleanup(self.crt_patch.stop)
        self.stat_patch = patch("scripts.daily_source_handles.os.fstat", return_value=SimpleNamespace(
            st_dev=19, st_ino=1 << 100, st_size=4, st_mtime_ns=123))
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)
        self.close_patch = patch("scripts.daily_source_handles.os.close",
                                 side_effect=lambda fd: self.fd_closed.append(fd))
        self.close_patch.start()
        self.addCleanup(self.close_patch.stop)

    def test_only_duplicate_transfers_and_closes_original_remains_owned(self):
        result = self.native.stat_identity(500)
        self.assertEqual(result, {"device": 19, "file_id": 1 << 100, "size": 4, "mtime_ns": 123})
        self.assertEqual(self.duplicates, [(500, 0, False, 2)])
        self.assertEqual(self.transfers, [700])
        self.assertEqual(self.fd_closed, [30])
        self.assertEqual(self.native_closed, [])

    def test_unknown_crt_transfer_retains_duplicate_without_guessing_ownership(self):
        def fail_transfer(handle, flags):
            raise RuntimeError("synthetic interrupted transfer")
        self.crt.open_osfhandle = fail_transfer
        with self.assertRaises(RuntimeError) as error:
            self.native.stat_identity(500)
        owners = error.exception._source_stat_custody
        self.assertEqual(len(owners), 1)
        for _ in range(5):
            with self.assertRaisesRegex(SourceFileError, "stat_custody_unknown"):
                owners[0].close()
        self.assertEqual(self.native_closed, [])
        self.assertEqual(self.fd_closed, [])

    def test_unknown_duplicate_output_is_preserved_without_close(self):
        def fail_duplicate(source, original, target, output, rights, inherit, options):
            output._obj.value = 701
            return False
        self.native.k.DuplicateHandle = fail_duplicate
        with self.assertRaisesRegex(SourceFileError, "stat_duplicate_failed") as error:
            self.native.stat_identity(500)
        self.assertEqual(len(error.exception._source_stat_custody), 1)
        self.assertEqual(self.transfers, [])
        self.assertEqual(self.native_closed, [])

    def test_unknown_crt_close_is_not_retried_by_native_or_fd_number(self):
        calls = []
        def interrupted_close(fd):
            calls.append(fd)
            raise RuntimeError("synthetic close completion unknown")
        with patch("scripts.daily_source_handles.os.close", side_effect=interrupted_close):
            with self.assertRaises(RuntimeError) as error:
                self.native.stat_identity(500)
        owner = error.exception._source_stat_custody[0]
        with self.assertRaisesRegex(SourceFileError, "stat_custody_unknown"):
            owner.close()
        self.assertEqual(calls, [30])
        self.assertEqual(self.native_closed, [])

    def test_known_failed_duplicate_close_retries_only_exact_duplicate(self):
        owner = _StatDuplicate(self.native)
        owner.acquire(500)
        attempts = []
        def failed_close(handle):
            attempts.append(handle)
            raise SourceFileError("source_close_failed", known_failed=True)
        self.native.close = failed_close
        with self.assertRaisesRegex(SourceFileError, "source_close_failed"):
            owner.close()
        self.native.close = lambda handle: attempts.append(handle)
        owner.close()
        owner.close()
        self.assertEqual(attempts, [700, 700])

    def test_native_open_masks_and_dispositions_are_explicit(self):
        calls = []
        self.native.k.CreateFileW = lambda *args: calls.append(args) or 800
        self.native.open(TARGET, directory=False, new=False)
        self.native.open(NEW, directory=False, new=True)
        self.native.open(r"C:\repo", directory=True, new=False)
        self.assertEqual([(item[1], item[2], item[4], item[5]) for item in calls], [
            (0xC0000000, 1, 3, 0x00200000),
            (0xC0010000, 1, 1, 0x00200000),
            (0x00100080, 1, 3, 0x02200000),
        ])
        self.assertTrue(all(item[0].startswith("\\\\?\\C:\\") for item in calls))


class ParentDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.files = NativeSourceFiles(backend=self.backend)
        self.file = r"C:\repo\sentinel\adaptive\new.py"

    def test_existing_directories_are_only_held_without_creation(self):
        owner = self.files.prepare_parent_directories(TARGET)
        self.addCleanup(owner.close)
        self.assertEqual(owner.created_directories, ())
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.backend.opened, [("C:\\", True, False), (r"C:\repo", True, False)])

    def test_missing_parents_created_and_verified_one_component_at_a_time(self):
        owner = self.files.prepare_parent_directories(self.file)
        self.addCleanup(owner.close)
        self.assertEqual(owner.created_directories,
                         (r"C:\repo\sentinel", r"C:\repo\sentinel\adaptive"))
        self.assertNotIn(self.file, self.backend.nodes)
        self.assertEqual(self.backend.created, list(owner.created_directories))
        for held in owner._parents:
            self.assertIsNotNone(held.identity)
            self.assertIsNotNone(held.value)
        leaf = self.files.create_new(self.file)
        self.addCleanup(leaf.close)
        self.assertEqual(leaf.backup_bytes, b"")
        leaf.close()
        owner.close()
        self.assertTrue(all(path in self.backend.nodes for path in owner.created_directories))

    def test_reparse_ancestor_prevents_any_child_creation(self):
        self.backend.nodes[r"C:\repo"]["attributes"] |= 0x400
        with self.assertRaisesRegex(SourceFileError, "path_or_metadata_unverified") as error:
            self.files.prepare_parent_directories(self.file)
        self.addCleanup(error.exception.retained_directories.close)
        self.assertEqual(self.backend.created, [])

    def test_access_denied_is_not_misclassified_as_missing(self):
        original = self.backend.open
        def denied(path, *, directory, new):
            if path == r"C:\repo\sentinel":
                raise SourceFileError("source_open_failed", known_failed=True, win32_error=5)
            return original(path, directory=directory, new=new)
        self.backend.open = denied
        with self.assertRaisesRegex(SourceFileError, "source_open_failed") as error:
            self.files.prepare_parent_directories(self.file)
        self.addCleanup(error.exception.retained_directories.close)
        self.assertEqual(self.backend.created, [])

    def test_directory_appearing_in_race_is_verified_and_not_claimed_created(self):
        def existing_directory(path):
            self.backend.add(path, directory=True)
            return False
        self.backend.create_directory = existing_directory
        owner = self.files.prepare_parent_directories(self.file)
        self.addCleanup(owner.close)
        self.assertEqual(owner.created_directories, ())
        self.assertEqual(len(owner._parents), 4)

    def test_reparse_appearing_in_create_race_is_not_followed(self):
        def existing_reparse(path):
            self.backend.add(path, directory=True, attributes=0x410)
            return False
        self.backend.create_directory = existing_reparse
        with self.assertRaisesRegex(SourceFileError, "path_or_metadata_unverified") as error:
            self.files.prepare_parent_directories(self.file)
        self.addCleanup(error.exception.retained_directories.close)
        self.assertNotIn(r"C:\repo\sentinel\adaptive", self.backend.nodes)

    def test_unknown_creation_retains_ancestors_and_is_not_retried(self):
        self.backend.failure = "create_directory"
        with self.assertRaisesRegex(SourceFileError, "directory_preparation_unverified") as error:
            self.files.prepare_parent_directories(self.file)
        owner = error.exception.retained_directories
        self.assertTrue(owner.quarantined)
        self.assertEqual(owner.created_directories, ())
        self.assertIn(r"C:\repo\sentinel", self.backend.nodes)
        self.backend.failure = None
        calls = list(self.backend.calls)
        for _ in range(3):
            with self.assertRaisesRegex(SourceFileError, "directory_create_outcome_unknown"):
                owner.close()
        self.assertEqual(self.backend.calls, calls)
        self.assertEqual(self.backend.closed, [])

    def test_created_directories_remain_on_later_failure(self):
        original = self.backend.create_directory
        def fail_second(path):
            if path.endswith("adaptive"):
                raise SourceFileError("source_directory_create_failed", known_failed=True, win32_error=5)
            return original(path)
        self.backend.create_directory = fail_second
        with self.assertRaisesRegex(SourceFileError, "directory_create_failed") as error:
            self.files.prepare_parent_directories(self.file)
        owner = error.exception.retained_directories
        self.assertEqual(owner.created_directories, (r"C:\repo\sentinel",))
        owner.close()
        self.assertTrue(owner.closed)
        self.assertIn(r"C:\repo\sentinel", self.backend.nodes)

    def test_known_failed_parent_close_is_retryable_unknown_is_not(self):
        for failure in ("close_known", "close"):
            with self.subTest(failure=failure):
                backend = Backend()
                owner = NativeSourceFiles(backend=backend).prepare_parent_directories(TARGET)
                backend.failure = failure
                with self.assertRaises(SourceFileError):
                    owner.close()
                calls = list(backend.calls)
                backend.failure = None
                if failure == "close_known":
                    owner.close()
                    self.assertEqual(backend.closed, [102, 101])
                else:
                    with self.assertRaisesRegex(SourceFileError, "handle_outcome_unknown"):
                        owner.close()
                    self.assertEqual(backend.calls, calls)
                    self.assertEqual(backend.closed, [])

    def test_missing_drive_root_is_not_created(self):
        del self.backend.nodes["C:\\"]
        with self.assertRaisesRegex(SourceFileError, "source_open_failed") as error:
            self.files.prepare_parent_directories(self.file)
        error.exception.retained_directories.close()
        self.assertEqual(self.backend.created, [])


if __name__ == "__main__":
    unittest.main()
