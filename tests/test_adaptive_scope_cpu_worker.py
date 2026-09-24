"""Portable workload protocol/custody tests; these do not establish native gates."""
from pathlib import Path
from contextlib import ExitStack
import ctypes
import hashlib
import json
import os
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.fixtures import adaptive_scope_cpu_worker as worker


GENERATION = "12345678-1234-4234-9234-123456789abc"
SCOPE_ID = "22345678-1234-4234-9234-123456789abc"
NONCE = "a" * 32
NOW = 100_000_000_000
IDENTITY = {"pid": 1234, "created_filetime_100ns": "130000000000000001", "logon_id": "S-1-5-5-123-456"}


class WorkloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.args = worker.parser().parse_args([
            "--canonical-root", str(self.directory), "--source-generation", GENERATION,
            "--source-digest", "b" * 64, "--fixture-sha256", "c" * 64,
            "--nonce", NONCE, "--job-name", worker.JOB_PREFIX + NONCE,
            "--directory", str(self.directory), "--seconds", "10",
            "--scope-id", SCOPE_ID, "--scope-bound-stdin"])
        self.owners = []
        self.addCleanup(self.clear_owners)

    def clear_owners(self):
        for owner in self.owners:
            if owner in worker._RETAINED:
                worker._RETAINED.remove(owner)

    def modules(self):
        process = Mock()
        process.identity = SimpleNamespace(logon_id=IDENTITY["logon_id"], to_dict=lambda: dict(IDENTITY))
        process.is_in_job.return_value = True
        job = Mock(handle=88)
        modules = SimpleNamespace(
            identity=SimpleNamespace(VerifiedProcess=SimpleNamespace(current=Mock(return_value=process))),
            jobs=SimpleNamespace(NativeJob=SimpleNamespace(open=Mock(return_value=job)),
                                 JobAccess=SimpleNamespace(QUERY="QUERY")),
            host=SimpleNamespace(read_host_capability=Mock(), HostCapabilityUnsupported=ProbeRefusal))
        return modules, process, job

    def owner(self):
        modules, process, job = self.modules()
        owner = worker.WorkloadOwner(self.args, self.directory, NOW + 10_000_000_000, modules)
        self.owners.append(owner)
        owner.process, owner.job = process, job
        return owner

    def ready(self):
        return {"identity": dict(IDENTITY), "nonce": NONCE, "job_name": worker.JOB_PREFIX + NONCE,
                "scope_id": SCOPE_ID,
                "source_generation": GENERATION, "source_digest": "b" * 64, "fixture_sha256": "c" * 64,
                "deadline_monotonic_ns": NOW + 10_000_000_000, "in_expected_job": True,
                "role": "leaf", "status": "ready", "schema_version": 1}

    def verify(self, record):
        worker.verify_ready(record, identity=IDENTITY, args=self.args, deadline=NOW + 10_000_000_000)

    def test_shared_deadline_is_never_extended_by_child(self):
        self.args.leaf, self.args.deadline_monotonic_ns = True, NOW + 5_000_000_000
        self.args.scope_bound_stdin = False
        self.assertEqual(worker.validate(self.args, NOW)[1], NOW + 5_000_000_000)
        self.assertEqual(worker.validate(self.args, NOW + 1_000_000_000)[1], NOW + 5_000_000_000)

    def test_duration_bounds_and_nonfinite_values(self):
        for value in (0, -1, 115.001, float("inf"), float("nan"), True):
            self.args.seconds = value
            with self.subTest(value=value), self.assertRaises(worker.FixtureError):
                worker.validate(self.args, NOW)
        self.args.seconds = 115
        self.assertEqual(worker.validate(self.args, NOW)[1], NOW + worker.MAX_NS)

    def test_worker_count_covers_s1_saturation_without_unbounded_spawn(self):
        for value in (1, 9, 32, 64):
            self.args.workers = value
            worker.validate(self.args, NOW)
        for value in (0, 65, True, 1.5):
            self.args.workers = value
            with self.subTest(value=value), self.assertRaises(worker.FixtureError):
                worker.validate(self.args, NOW)

    def test_only_exact_test_job_nonce_is_accepted(self):
        for name in ("Local\\ResourceSentinel.Test.Job." + "d" * 32,
                     "Local\\ResourceSentinel.Job." + GENERATION + "." + NONCE,
                     "Global\\ResourceSentinel.Test.Job." + NONCE):
            self.args.job_name = name
            with self.subTest(name=name), self.assertRaisesRegex(worker.FixtureError, "fixture_job_invalid"):
                worker.validate(self.args, NOW)

    def test_pin_shapes_are_required(self):
        for name, value in (("source_generation", "0" * 32), ("source_digest", "B" * 64),
                            ("fixture_sha256", "a" * 63), ("nonce", "A" * 32)):
            original = getattr(self.args, name)
            setattr(self.args, name, value)
            with self.subTest(name=name), self.assertRaises(worker.FixtureError):
                worker.validate(self.args, NOW)
            setattr(self.args, name, original)

    def test_leaf_requires_original_deadline_and_cannot_spawn(self):
        self.args.leaf = True
        self.args.scope_bound_stdin = False
        with self.assertRaisesRegex(worker.FixtureError, "fixture_leaf_invalid"):
            worker.validate(self.args, NOW)
        self.args.deadline_monotonic_ns = NOW + 5_000_000_000
        self.args.workers = 2
        with self.assertRaisesRegex(worker.FixtureError, "fixture_leaf_invalid"):
            worker.validate(self.args, NOW)

    def test_expired_and_overlong_deadlines_refused(self):
        self.args.leaf, self.args.scope_bound_stdin = True, False
        for deadline in (NOW, NOW - 1, NOW + worker.MAX_NS + 1, True):
            self.args.deadline_monotonic_ns = deadline
            with self.subTest(deadline=deadline), self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_invalid"):
                worker.validate(self.args, NOW)

    def test_foreign_probe_cannot_request_children(self):
        self.args.probe_foreign_host, self.args.workers = True, 2
        with self.assertRaisesRegex(worker.FixtureError, "fixture_probe_must_not_spawn"):
            worker.validate(self.args, NOW)

    def test_daily_data_directory_refused(self):
        path = self.directory / ".resource-sentinel"
        path.mkdir()
        self.args.directory = path
        with patch.object(worker.Path, "home", return_value=self.directory):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_directory_must_be_isolated"):
                worker.validate(self.args, NOW)

    def test_recursive_command_preserves_all_pins_and_isolation(self):
        command = worker.child_command(self.args, NOW + 5_000_000_000)
        self.assertEqual(command[1], "-I")
        leaf = worker.parser().parse_args(command[3:])
        for name in ("canonical_root", "source_generation", "source_digest", "fixture_sha256", "nonce", "job_name", "directory"):
            self.assertEqual(getattr(leaf, name), getattr(self.args, name))
        self.assertEqual(leaf.deadline_monotonic_ns, NOW + 5_000_000_000)
        self.assertTrue(leaf.leaf)
        self.assertEqual(leaf.scope_id, SCOPE_ID)
        self.assertFalse(leaf.scope_bound_stdin)
        self.assertEqual(leaf.workers, 1)

    def timing_record(self, **changes):
        return dict(schema_version=1, kind="S1ScopeTiming", scope_id=SCOPE_ID,
                    job_nonce=NONCE, source_generation=GENERATION, source_digest="b" * 64,
                    fixture_sha256="c" * 64,
                    scope_deadline_monotonic_ns=NOW + worker.MAX_SCOPE_NS) | changes

    def timing_file(self, *, record=None, raw=None):
        stream = tempfile.TemporaryFile(mode="w+b")
        self.addCleanup(stream.close)
        if raw is None:
            raw = json.dumps(self.timing_record() if record is None else record,
                             separators=(",", ":")).encode("utf-8")
        stream.write(raw)
        stream.flush()
        stream.seek(0)
        return stream

    def read_timing(self, stream, *, now=NOW):
        with patch.object(worker.time, "monotonic_ns", return_value=now):
            return worker.read_scope_timing(self.args, NOW, fd=stream.fileno())

    def test_root_requires_scope_uuid_and_stdin_mode_without_clock_argument(self):
        for name, value in (("scope_id", None), ("scope_bound_stdin", False),
                            ("deadline_monotonic_ns", NOW + 5_000_000_000)):
            original = getattr(self.args, name)
            setattr(self.args, name, value)
            with self.subTest(name=name), self.assertRaisesRegex(worker.FixtureError, "fixture_scope_timing_required"):
                worker.validate(self.args, NOW)
            setattr(self.args, name, original)
        self.args.scope_id = "0" * 32
        with self.assertRaisesRegex(worker.FixtureError, "fixture_uuid_invalid"):
            worker.validate(self.args, NOW)

    def test_leaf_refuses_root_stdin_mode_and_keeps_exact_cutoff(self):
        self.args.leaf, self.args.deadline_monotonic_ns = True, NOW + 5_000_000_000
        with patch.object(worker.os, "read") as read:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_leaf_invalid"):
                worker.validate(self.args, NOW)
            with self.assertRaisesRegex(worker.FixtureError, "fixture_scope_timing_required"):
                worker.read_scope_timing(self.args, NOW)
        read.assert_not_called()
        self.args.scope_bound_stdin = False
        self.assertEqual(worker.validate(self.args, NOW)[1], self.args.deadline_monotonic_ns)
        self.args.seconds = 2
        with self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_invalid"):
            worker.validate(self.args, NOW)

    def test_timing_uses_real_regular_stdin_and_leaves_original_descriptor_open(self):
        stream = self.timing_file()
        self.assertTrue(stat.S_ISREG(os.fstat(stream.fileno()).st_mode))
        self.assertEqual(self.read_timing(stream), NOW + 10_000_000_000)
        self.assertFalse(stream.closed)
        self.assertEqual(os.lseek(stream.fileno(), 0, os.SEEK_CUR), os.fstat(stream.fileno()).st_size)
        self.assertEqual(os.read(stream.fileno(), 1), b"")

    def test_timing_scope_minus_grace_bounds_root_and_same_leaf_deadline(self):
        self.args.seconds = 115
        stream = self.timing_file(record=self.timing_record(scope_deadline_monotonic_ns=NOW + 100_000_000_000))
        deadline = self.read_timing(stream)
        self.assertEqual(deadline, NOW + 96_000_000_000)
        leaf = worker.parser().parse_args(worker.child_command(self.args, deadline)[3:])
        self.assertEqual(worker.validate(leaf, NOW + 7_000_000_000)[1], deadline)
        self.assertEqual(deadline + worker.COOPERATIVE_GRACE_NS, NOW + 100_000_000_000)

    def test_exact_4096_byte_regular_timing_record_is_within_bound(self):
        raw = json.dumps(self.timing_record(), separators=(",", ":")).encode()
        padded = raw[:1] + b" " * (worker.MAX_TIMING_BYTES - len(raw)) + raw[1:]
        self.assertEqual(len(padded), worker.MAX_TIMING_BYTES)
        self.assertEqual(self.read_timing(self.timing_file(raw=padded)), NOW + 10_000_000_000)

    def test_two_second_prerequisite_remains_two_seconds(self):
        self.args.seconds = 2
        self.assertEqual(self.read_timing(self.timing_file()), NOW + 2_000_000_000)

    def test_nonregular_stdin_is_rejected_before_any_read_or_seek(self):
        with open(os.devnull, "rb") as stream, patch.object(worker.os, "read") as read, \
                patch.object(worker.os, "lseek") as seek:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_invalid"):
                worker.read_scope_timing(self.args, NOW, fd=stream.fileno())
        read.assert_not_called()
        seek.assert_not_called()

    def test_empty_oversized_and_nonzero_offset_inputs_refuse_before_read(self):
        for raw in (b"", b"x" * (worker.MAX_TIMING_BYTES + 1)):
            stream = self.timing_file(raw=raw)
            with self.subTest(size=len(raw)), patch.object(worker.os, "read") as read:
                with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_invalid"):
                    worker.read_scope_timing(self.args, NOW, fd=stream.fileno())
                read.assert_not_called()
        stream = self.timing_file()
        stream.seek(1)
        with patch.object(worker.os, "read") as read:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_invalid"):
                worker.read_scope_timing(self.args, NOW, fd=stream.fileno())
        read.assert_not_called()

    def test_each_timing_binding_and_exact_field_set_is_required(self):
        changes = (("schema_version", True), ("kind", "Other"),
                   ("scope_id", GENERATION), ("job_nonce", "d" * 32),
                   ("source_generation", SCOPE_ID), ("source_digest", "d" * 64),
                   ("fixture_sha256", "d" * 64))
        for key, value in changes:
            with self.subTest(key=key), self.assertRaisesRegex(worker.FixtureError, "fixture_timing_binding_changed"):
                self.read_timing(self.timing_file(record=self.timing_record(**{key: value})))
        for key in self.timing_record():
            value = self.timing_record()
            del value[key]
            with self.subTest(missing=key), self.assertRaisesRegex(worker.FixtureError, "fixture_timing_binding_changed"):
                self.read_timing(self.timing_file(record=value))
        with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_binding_changed"):
            self.read_timing(self.timing_file(record=self.timing_record(command_sha256="f" * 64)))

    def test_duplicate_nonfinite_invalid_utf8_and_trailing_json_are_rejected(self):
        raw = json.dumps(self.timing_record(), separators=(",", ":")).encode()
        payloads = (b'{"kind":"S1ScopeTiming",' + raw[1:], raw[:-1] + b',"x":NaN}',
                    raw + b"{}", raw + b"\n", b"\xff", b"[1]")
        for payload in payloads:
            with self.subTest(payload=payload[:32]), self.assertRaises(worker.FixtureError):
                self.read_timing(self.timing_file(raw=payload))

    def test_scope_deadline_type_maximum_and_expiry_are_strict(self):
        for value in (True, float(NOW + 10_000_000_000), NOW, NOW - 1,
                      NOW + worker.MAX_SCOPE_NS + 1):
            with self.subTest(value=value), self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_invalid"):
                self.read_timing(self.timing_file(record=self.timing_record(scope_deadline_monotonic_ns=value)))
        for value in (NOW + 1, NOW + worker.COOPERATIVE_GRACE_NS):
            with self.subTest(value=value), self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_expired"):
                self.read_timing(self.timing_file(record=self.timing_record(scope_deadline_monotonic_ns=value)))

    def test_file_growth_during_real_read_is_rejected(self):
        stream = self.timing_file()
        original_read = os.read
        changed = False

        def grow_after_read(fd, count):
            nonlocal changed
            result = original_read(fd, count)
            if not changed:
                changed = True
                os.write(fd, b"x")
            return result

        with patch.object(worker.os, "read", side_effect=grow_after_read):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_changed"):
                self.read_timing(stream)

    def test_descriptor_identity_change_after_read_is_rejected(self):
        stream = self.timing_file()
        original_stat = os.fstat
        calls = 0

        def changed_identity(fd):
            nonlocal calls
            calls += 1
            value = original_stat(fd)
            if calls == 1:
                return value
            fields = ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            return SimpleNamespace(**{key: getattr(value, key) + (key == "st_ino") for key in fields})

        with patch.object(worker.os, "fstat", side_effect=changed_identity):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_changed"):
                self.read_timing(stream)

    def test_short_regular_read_is_rejected_as_truncated(self):
        stream = self.timing_file()
        original_read = os.read
        with patch.object(worker.os, "read", side_effect=lambda fd, count: original_read(fd, min(count, 3))):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_timing_input_changed"):
                self.read_timing(stream)

    def test_regular_read_delay_consumes_original_deadline(self):
        stream = self.timing_file()
        original_read = os.read
        clock = {"now": NOW}

        def delayed_read(fd, count):
            result = original_read(fd, count)
            clock["now"] = NOW + 10_000_000_000
            return result

        with patch.object(worker.os, "read", side_effect=delayed_read), \
                patch.object(worker.time, "monotonic_ns", side_effect=lambda: clock["now"]):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_expired"):
                worker.read_scope_timing(self.args, NOW, fd=stream.fileno())

    def test_main_captures_start_before_parse_and_preserves_cutoff_through_bootstrap(self):
        stream = self.timing_file()
        actual_reader = worker.read_scope_timing
        clock = {"now": NOW}
        modules = object()

        def parse(_):
            clock["now"] += 2_000_000_000
            return self.args

        def bootstrap(_):
            clock["now"] += 3_000_000_000
            return modules

        with patch.object(worker.time, "monotonic_ns", side_effect=lambda: clock["now"]), \
                patch.object(worker, "parser", return_value=SimpleNamespace(parse_args=parse)), \
                patch.object(worker, "read_scope_timing", side_effect=lambda args, start: actual_reader(args, start, fd=stream.fileno())) as read, \
                patch.object(worker, "bootstrap", side_effect=bootstrap), patch.object(worker, "run", return_value=0) as run:
            self.assertEqual(worker.main([]), 0)
        read.assert_called_once_with(self.args, NOW)
        run.assert_called_once_with(self.args, self.directory, NOW + 10_000_000_000, modules)

    def test_bootstrap_expiry_refuses_before_workload_native_setup(self):
        stream = self.timing_file()
        actual_reader = worker.read_scope_timing
        clock = {"now": NOW}

        def bootstrap(_):
            clock["now"] = NOW + 10_000_000_000
            return object()

        with patch.object(worker.time, "monotonic_ns", side_effect=lambda: clock["now"]), \
                patch.object(worker, "parser", return_value=SimpleNamespace(parse_args=lambda _: self.args)), \
                patch.object(worker, "read_scope_timing", side_effect=lambda args, start: actual_reader(args, start, fd=stream.fileno())), \
                patch.object(worker, "bootstrap", side_effect=bootstrap), patch.object(worker, "run") as run:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_deadline_expired"):
                worker.main([])
        run.assert_not_called()

    def test_leaf_main_never_reads_stdin_and_uses_parent_deadline(self):
        self.args.leaf, self.args.scope_bound_stdin = True, False
        self.args.deadline_monotonic_ns = NOW + 5_000_000_000
        modules = object()
        with patch.object(worker.time, "monotonic_ns", return_value=NOW), \
                patch.object(worker, "parser", return_value=SimpleNamespace(parse_args=lambda _: self.args)), \
                patch.object(worker, "read_scope_timing") as read, \
                patch.object(worker, "bootstrap", return_value=modules), patch.object(worker, "run", return_value=0) as run:
            self.assertEqual(worker.main([]), 0)
        read.assert_not_called()
        run.assert_called_once_with(self.args, self.directory, self.args.deadline_monotonic_ns, modules)

    def test_bootstrap_refuses_nonisolated_interpreter_before_import(self):
        with patch.object(worker.sys, "flags", SimpleNamespace(isolated=0)), patch.object(worker.importlib, "import_module") as load:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_isolated_opt_in_required"):
                worker.bootstrap(self.args)
            load.assert_not_called()

    def test_bootstrap_refuses_preloaded_sentinel_before_import(self):
        with patch.object(worker.sys, "flags", SimpleNamespace(isolated=1)), \
                patch.dict(worker.os.environ, {worker.OPT_IN: "1"}), \
                patch.dict(worker.sys.modules, {"sentinel": object()}), \
                patch.object(worker.importlib, "import_module") as load:
            with self.assertRaisesRegex(worker.FixtureError, "fixture_sentinel_preloaded"):
                worker.bootstrap(self.args)
            load.assert_not_called()

    def bootstrap_fixture(self, *, digest=None, canonical=None):
        source = self.directory / "Projects" / "resource-sentinel"
        source.mkdir(parents=True)
        self.args.canonical_root = canonical or source
        self.args.fixture_sha256 = hashlib.sha256(Path(worker.__file__).read_bytes()).hexdigest()
        manifest = SimpleNamespace(digest=digest or self.args.source_digest)
        generation = SimpleNamespace(SourceManifest=SimpleNamespace(capture=Mock(return_value=manifest)),
                                     verify_import_provenance=Mock())
        imported = {"sentinel.adaptive.daily_generation": generation,
                    "sentinel.adaptive.identity": object(), "sentinel.adaptive.native_job": object(),
                    "sentinel.adaptive.host_authority": object()}
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(worker.Path, "home", return_value=self.directory))
        stack.enter_context(patch.object(worker.sys, "flags", SimpleNamespace(isolated=1)))
        stack.enter_context(patch.object(worker.sys, "modules", {}))
        stack.enter_context(patch.object(worker.sys, "path", []))
        stack.enter_context(patch.dict(worker.os.environ, {worker.OPT_IN: "1"}))
        loader = stack.enter_context(patch.object(worker.importlib, "import_module", side_effect=imported.__getitem__))
        return source, generation, manifest, loader

    def test_canonical_bootstrap_verifies_actual_manifest_and_import_provenance(self):
        source, generation, manifest, loader = self.bootstrap_fixture()
        result = worker.bootstrap(self.args)
        self.assertEqual(result.root, source)
        self.assertEqual(worker.sys.path, [str(source)])
        generation.SourceManifest.capture.assert_called_once_with(source)
        generation.verify_import_provenance.assert_called_once_with(manifest, source)
        self.assertEqual(loader.call_count, 4)

    def test_changed_source_digest_refused_before_native_ownership(self):
        source, generation, manifest, loader = self.bootstrap_fixture(digest="f" * 64)
        with self.assertRaisesRegex(worker.FixtureError, "fixture_source_generation_mismatch"):
            worker.bootstrap(self.args)
        generation.verify_import_provenance.assert_not_called()

    def test_worktree_canonical_root_substitution_refused(self):
        source, generation, manifest, loader = self.bootstrap_fixture(canonical=self.directory)
        with self.assertRaisesRegex(worker.FixtureError, "fixture_canonical_root_mismatch"):
            worker.bootstrap(self.args)
        loader.assert_not_called()

    def test_changed_fixture_source_refused_before_import(self):
        source, generation, manifest, loader = self.bootstrap_fixture()
        self.args.fixture_sha256 = "0" * 64
        with self.assertRaisesRegex(worker.FixtureError, "fixture_source_changed"):
            worker.bootstrap(self.args)
        loader.assert_not_called()

    def test_child_ready_uses_exact_native_birth_logon_and_source_pins(self):
        self.verify(self.ready())
        for key, changed in (("identity", {**IDENTITY, "created_filetime_100ns": "130000000000000002"}),
                             ("scope_id", GENERATION),
                             ("source_generation", "22345678-1234-4234-9234-123456789abc"),
                             ("source_digest", "d" * 64), ("fixture_sha256", "d" * 64),
                             ("deadline_monotonic_ns", NOW + 11_000_000_000),
                             ("in_expected_job", 1), ("role", "root"), ("schema_version", True)):
            record = self.ready()
            record[key] = changed
            with self.subTest(key=key), self.assertRaisesRegex(worker.FixtureError, "fixture_child_ready_mismatch"):
                self.verify(record)

    def test_existing_evidence_cannot_be_overwritten(self):
        path = self.directory / "ready-1234.json"
        worker.publish(path, {"original": 1})
        with self.assertRaises(FileExistsError):
            worker.publish(path, {"replacement": 2})
        self.assertEqual(worker.read_ready(path), {"original": 1})

    def test_evidence_reader_rejects_duplicates_nonfinite_and_oversize(self):
        path = self.directory / "bad.json"
        for payload in (b'{"a":1,"a":2}', b'{"a":NaN}', b"x" * 65537):
            path.write_bytes(payload)
            with self.subTest(payload=payload[:32]), self.assertRaises(worker.FixtureError):
                worker.read_ready(path)

    def test_stop_file_avoids_cpu_work(self):
        stop = self.directory / "stop"
        stop.touch()
        with patch.object(worker.time, "monotonic_ns", return_value=NOW):
            self.assertEqual(worker.cpu_work(NOW + 10, stop), (0, "stop_file"))

    def test_expired_deadline_avoids_cpu_work(self):
        with patch.object(worker.time, "monotonic_ns", return_value=NOW):
            self.assertEqual(worker.cpu_work(NOW, self.directory / "stop"), (0, "self_deadline"))

    def test_owner_opens_query_only_and_refuses_unknown_membership(self):
        owner = self.owner()
        owner.process.is_in_job.return_value = None
        with self.assertRaisesRegex(worker.FixtureError, "fixture_membership_unverified"):
            owner.open()
        self.assertEqual(owner.modules.jobs.NativeJob.open.call_args.kwargs, {"access": "QUERY"})

    def test_uncertain_close_retains_same_owner_and_is_never_retried(self):
        owner = self.owner()
        error = OSError("synthetic close ACK loss")
        owner.job.close.side_effect = error
        self.assertFalse(owner.settle())
        self.assertFalse(owner.settle())
        self.assertIn(owner, worker._RETAINED)
        self.assertIs(owner.errors[-1], error)
        owner.job.close.assert_called_once()
        owner.process.close.assert_not_called()

    def test_helper_partial_native_owner_is_retained(self):
        owner = self.owner()
        error = OSError("synthetic duplicate ACK loss")
        original = object()
        error._identity_handle_cleanup = (original,)
        owner.errors.append(error)
        self.assertFalse(owner.settle())
        self.assertIs(owner.errors[0]._identity_handle_cleanup[0], original)
        owner.job.close.assert_not_called()

    def test_unknown_child_creation_cannot_settle(self):
        owner = self.owner()
        owner.children.append({"state": "creation_unknown"})
        self.assertFalse(owner.settle())
        self.assertTrue(owner.quarantined)
        owner.job.close.assert_not_called()

    def test_live_child_keeps_original_handles_and_can_later_settle(self):
        owner = self.owner()
        child = {"state": "owned"}
        owner.children.append(child)
        owner.native = Mock()
        owner.native.alive.side_effect = [True, False]
        self.assertFalse(owner.settle())
        owner.native.close_child.assert_not_called()
        self.assertTrue(owner.settle())
        owner.native.close_child.assert_called_once_with(child)
        self.assertNotIn(owner, worker._RETAINED)

    def run_synthetic(self, modules, *, native=None):
        with patch.object(worker, "NativeChildren", return_value=native or Mock()), \
                patch.object(worker.time, "monotonic_ns", return_value=NOW), \
                patch.object(worker, "cpu_work", return_value=(1, "self_deadline")) as burn:
            result = worker.run(self.args, self.directory, NOW + 10_000_000_000, modules)
        return result, burn

    def test_probe_reports_actual_parent_job_refusal_and_never_runs_cpu(self):
        modules, process, job = self.modules()
        self.args.probe_foreign_host = True
        modules.host.read_host_capability.side_effect = ProbeRefusal("host_foreign_parent_job")
        native = Mock()
        result, burn = self.run_synthetic(modules, native=native)
        self.assertEqual(result, 0)
        burn.assert_not_called()
        native.spawn.assert_not_called()
        self.assertFalse(list(self.directory.glob("ready-*.json")))
        self.assertEqual(worker.read_ready(self.directory / "foreign-probe.json")["foreign_gate"]["reason"],
                         "host_foreign_parent_job")
        self.assertTrue(worker.read_ready(self.directory / "exit-1234.json")["owned_handles_closed"])

    def test_probe_unknown_membership_is_not_expected_refusal(self):
        modules, process, job = self.modules()
        self.args.probe_foreign_host = True
        modules.host.read_host_capability.side_effect = ProbeRefusal("host_parent_job_membership_unknown")
        with self.assertRaises(ProbeRefusal):
            self.run_synthetic(modules)
        self.assertFalse((self.directory / "foreign-probe.json").exists())
        self.assertFalse((self.directory / "exit-1234.json").exists())

    def test_membership_failure_emits_no_ready_or_cpu(self):
        modules, process, job = self.modules()
        process.is_in_job.return_value = False
        with patch.object(worker, "cpu_work") as burn, \
                patch.object(worker.time, "monotonic_ns", return_value=NOW):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_membership_unverified"):
                worker.run(self.args, self.directory, NOW + 10_000_000_000, modules)
        burn.assert_not_called()
        self.assertFalse(list(self.directory.glob("ready-*.json")))
        self.assertFalse(list(self.directory.glob("exit-*.json")))

    def test_successful_leaf_records_only_after_membership_then_handle_cleanup(self):
        modules, process, job = self.modules()
        self.args.leaf, self.args.scope_bound_stdin = True, False
        result, burn = self.run_synthetic(modules)
        self.assertEqual(result, 0)
        self.assertEqual(worker.read_ready(self.directory / "ready-1234.json")["identity"], IDENTITY)
        exit_record = worker.read_ready(self.directory / "exit-1234.json")
        self.assertEqual(exit_record["children_still_alive"], 0)
        self.assertEqual(exit_record["status"], "work_complete")
        self.assertFalse((self.directory / "stop").exists())
        process.close.assert_called_once()
        job.close.assert_called_once()

    def raw_native(self):
        """Only Python fake calls and local ctypes output cells; no Win32 API."""
        clock = patch.object(worker.time, "monotonic_ns", return_value=NOW)
        clock.start()
        self.addCleanup(clock.stop)
        native = worker.NativeChildren.__new__(worker.NativeChildren)
        class Startup(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_uint32)]
        class Info(ctypes.Structure):
            _fields_ = [("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                        ("dwProcessId", ctypes.c_uint32), ("dwThreadId", ctypes.c_uint32)]
        native.c, native.Startup, native.Info = ctypes, Startup, Info
        native.create, native.wait, native.close = Mock(), Mock(return_value=0), Mock(return_value=1)
        owner = self.owner()
        owner.native = native
        verified = Mock()
        verified.identity = SimpleNamespace(to_dict=lambda: dict(IDENTITY))
        verified.is_in_job.return_value = True
        owner.modules.identity.VerifiedProcess.duplicate_from_handle = Mock(return_value=verified)
        def created(*args):
            self.assertEqual(len(owner.children), 1)
            self.assertEqual(owner.children[0]["state"], "creation_unknown")
            info = args[-1]._obj
            info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId = 81, 82, 1234, 5678
            return 1
        native.create.side_effect = created
        return native, owner, verified

    def test_child_deadline_expiring_during_buffer_preparation_never_enters_create(self):
        native, owner, verified = self.raw_native()
        original_deadline = owner.deadline
        original_job, original_process = owner.job, owner.process
        original_buffer = ctypes.create_unicode_buffer
        clock = {"now": NOW}

        def consume_remaining_time(value):
            self.assertEqual(len(owner.children), 1)
            self.assertEqual(owner.children[0]["state"], "not_attempted")
            buffer = original_buffer(value)
            clock["now"] = original_deadline
            return buffer

        with patch.object(worker.time, "monotonic_ns", side_effect=lambda: clock["now"]), \
                patch.object(native.c, "create_unicode_buffer", side_effect=consume_remaining_time):
            with self.assertRaisesRegex(worker.FixtureError, "fixture_stopped_before_child") as caught:
                native.spawn(["python.exe", "-I", "fixture.py"], owner)
        owner.errors.append(caught.exception)  # The same error retained by run().
        self.assertEqual(owner.deadline, original_deadline)
        self.assertEqual(len(owner.children), 1)
        child = owner.children[0]
        self.assertEqual(child["state"], "not_attempted")
        self.assertFalse(any((child["info"].hProcess, child["info"].hThread,
                              child["info"].dwProcessId, child["info"].dwThreadId)))
        self.assertIsNone(child["verified"])
        native.create.assert_not_called()
        owner.modules.identity.VerifiedProcess.duplicate_from_handle.assert_not_called()
        self.assertIn(owner, worker._RETAINED)
        self.assertTrue(owner.settle())
        self.assertIs(owner.children[0], child)
        self.assertIs(owner.job, original_job)
        self.assertIs(owner.process, original_process)
        self.assertFalse(owner.quarantined)
        self.assertNotIn(owner, worker._RETAINED)
        native.wait.assert_not_called()
        native.close.assert_not_called()
        verified.close.assert_not_called()
        original_job.close.assert_called_once()
        original_process.close.assert_called_once()

    def test_native_create_retains_outputs_before_call_and_only_inherits_job(self):
        native, owner, verified = self.raw_native()
        child = native.spawn(["python.exe", "-I", "fixture.py"], owner)
        self.assertEqual(child["state"], "owned")
        self.assertEqual(child["identity"], IDENTITY)
        call = native.create.call_args.args
        self.assertIs(call[4], False)  # no inheritable handles
        self.assertEqual(call[5], 0x08000000)  # no breakaway or suspended launch
        owner.modules.identity.VerifiedProcess.duplicate_from_handle.assert_called_once_with(
            81, expected_pid=1234, expected_logon_id=IDENTITY["logon_id"])
        verified.is_in_job.assert_called_once_with(owner.job.handle)

    def test_native_false_with_zero_outputs_is_known_absent(self):
        native, owner, verified = self.raw_native()
        native.create.side_effect = lambda *_: 0
        with self.assertRaisesRegex(worker.FixtureError, "fixture_child_create_failed"):
            native.spawn(["python.exe"], owner)
        self.assertEqual(owner.children[0]["state"], "absent")
        self.assertTrue(owner.settle())
        native.close.assert_not_called()

    def test_native_false_with_partial_outputs_retains_original_cells(self):
        native, owner, verified = self.raw_native()
        def partial(*args):
            args[-1]._obj.hProcess = 81
            return 0
        native.create.side_effect = partial
        with self.assertRaises(worker.RetainedOwnerError) as result:
            native.spawn(["python.exe"], owner)
        self.assertIs(result.exception.owner, owner)
        self.assertEqual(owner.children[0]["info"].hProcess, 81)
        self.assertFalse(owner.settle())
        native.close.assert_not_called()

    def test_native_create_ack_exception_retains_original_error_and_cells(self):
        native, owner, verified = self.raw_native()
        original = OSError("synthetic create ACK loss")
        def partial(*args):
            args[-1]._obj.hThread = 82
            raise original
        native.create.side_effect = partial
        with self.assertRaises(worker.RetainedOwnerError) as result:
            native.spawn(["python.exe"], owner)
        self.assertIs(result.exception.owner, owner)
        self.assertIs(owner.errors[0], original)
        self.assertEqual(owner.children[0]["info"].hThread, 82)
        self.assertFalse(owner.settle())

    def test_native_success_with_incomplete_outputs_does_not_assume_ownership(self):
        native, owner, verified = self.raw_native()
        def partial(*args):
            args[-1]._obj.hProcess = 81
            return 1
        native.create.side_effect = partial
        with self.assertRaisesRegex(worker.RetainedOwnerError, "fixture_child_handles_unknown"):
            native.spawn(["python.exe"], owner)
        self.assertFalse(owner.settle())
        native.wait.assert_not_called()

    def test_native_duplicate_partial_owner_stays_with_creation(self):
        native, owner, verified = self.raw_native()
        original = OSError("synthetic duplicate cleanup")
        duplicate_owner = object()
        original._identity_handle_cleanup = (duplicate_owner,)
        owner.modules.identity.VerifiedProcess.duplicate_from_handle.side_effect = original
        with self.assertRaises(OSError) as result:
            native.spawn(["python.exe"], owner)
        owner.errors.append(result.exception)  # same exception run() retains
        self.assertEqual(owner.children[0]["state"], "owned")
        self.assertFalse(owner.settle())
        self.assertIs(owner.errors[0]._identity_handle_cleanup[0], duplicate_owner)
        native.close.assert_not_called()

    def test_native_wait_unknown_never_means_exit_and_only_read_may_retry(self):
        native, owner, verified = self.raw_native()
        native.spawn(["python.exe"], owner)
        native.wait.side_effect = [0xffffffff, 0, 0]
        self.assertFalse(owner.settle())
        self.assertFalse(owner.quarantined)
        native.close.assert_not_called()
        self.assertTrue(owner.settle())

    def test_native_thread_close_ack_loss_cannot_retry_close(self):
        native, owner, verified = self.raw_native()
        child = native.spawn(["python.exe"], owner)
        native.close.side_effect = OSError("synthetic thread close ACK loss")
        self.assertFalse(owner.settle())
        self.assertEqual(child["closing"], "hThread")
        self.assertFalse(owner.settle())
        native.close.assert_called_once_with(82)
        verified.close.assert_called_once()

    def test_second_native_wait_failure_before_close_can_retry_only_observation(self):
        native, owner, verified = self.raw_native()
        native.spawn(["python.exe"], owner)
        native.wait.side_effect = [0, 0xffffffff, 0, 0]
        self.assertFalse(owner.settle())
        self.assertFalse(owner.quarantined)
        native.close.assert_not_called()
        verified.close.assert_not_called()
        self.assertTrue(owner.settle())

    def test_native_process_close_ack_loss_keeps_already_closed_thread_retired(self):
        native, owner, verified = self.raw_native()
        child = native.spawn(["python.exe"], owner)
        native.close.side_effect = [1, OSError("synthetic process close ACK loss")]
        self.assertFalse(owner.settle())
        self.assertEqual(child["closing"], "hProcess")
        self.assertIn("hThread", child["closed"])
        self.assertFalse(owner.settle())
        self.assertEqual(native.close.call_count, 2)


class ProbeRefusal(RuntimeError):
    def __init__(self, reason):
        self.reason, self.win32_error = reason, None
        super().__init__(reason)


if __name__ == "__main__":
    unittest.main()
