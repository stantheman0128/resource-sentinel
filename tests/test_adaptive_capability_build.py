"""Actual isolated file inventories and synthetic evidence; no native gate."""
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import capability_build as cb, capability_evidence as ce
from sentinel.adaptive import daily_generation as generation
from tests import test_adaptive_capability_evidence as fixtures


class CapabilityBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sentinel-bound-build-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime, self.producer = self.root / "daily", self.root / "reviewed"
        for name in generation.REQUIRED_PATHS:
            path = self.runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# isolated source\n", encoding="utf-8")
        for name in ("windows", "benchmarks", "fixtures"):
            path = self.producer / "tests" / name / "fixture.py"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# " + name + "\n", encoding="utf-8")
        for override in (patch.object(ce, "_ROOT", self.runtime),
                         patch.object(cb, "daily_locations", return_value=(self.runtime, self.root / "data")),
                         # Actual production imports remain in this worktree.
                         # Explicit fixture attestation, not native provenance.
                         patch.object(cb, "verify_import_provenance", return_value=self.runtime)):
            override.start()
            self.addCleanup(override.stop)
        self.binding = cb.SourceBinding(1, "canonical_runtime_fixture_inventory",
            str(self.runtime), str(self.producer), generation.SourceManifest.capture(self.runtime).digest)

    def source(self):
        return cb.SourceBoundBuildSource(self.binding)

    def test_actual_separate_inventory_hashes_use_relative_labels(self):
        observed = self.source()()
        runtime_paths = tuple((self.runtime / "sentinel").rglob("*.py")) + (
            self.runtime / "scripts" / "invoke-sentinel.ps1",)
        producer_paths = tuple((self.producer / "tests").rglob("*.py"))
        def digest(paths, root):
            records = [p.relative_to(root).as_posix() + "\0" + hashlib.sha256(p.read_bytes()).hexdigest() + "\n"
                       for p in sorted(paths)]
            return hashlib.sha256("".join(records).encode()).hexdigest()
        self.assertEqual(observed, ce.BuildIdentity(digest(runtime_paths, self.runtime),
            digest(producer_paths, self.producer)))
        self.assertEqual(cb.SourceBinding.from_dict(self.binding.to_dict()), self.binding)
        with self.assertRaises(FrozenInstanceError):
            self.binding.producer_root = str(self.runtime)

    def test_runtime_source_change_refuses_original_generation(self):
        reader = self.source()
        reader()
        (self.runtime / "sentinel" / "coordinator.py").write_text("# changed\n")
        with self.assertRaises(generation.DailyGenerationUnavailable):
            reader()

    def test_producer_change_refuses_original_build(self):
        reader = self.source()
        reader()
        (self.producer / "tests/windows/fixture.py").write_text("# changed\n")
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_build_changed"):
            reader()

    def test_producer_addition_and_removal_refuse_inventory_refresh(self):
        for add in (True, False):
            with self.subTest(add=add):
                reader = self.source()
                reader()
                path = self.producer / "tests/windows/additional.py"
                if add:
                    path.write_text("# new\n")
                else:
                    path.unlink()
                with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_build_inventory_changed"):
                    reader()

    def test_actual_runtime_addition_and_removal_refuse_original_manifest(self):
        for add in (True, False):
            with self.subTest(add=add):
                reader = self.source()
                reader()
                path = self.runtime / "sentinel/additional.py" if add else self.runtime / "sentinel/coordinator.py"
                if add:
                    path.write_text("# new runtime\n")
                else:
                    path.unlink()
                with self.assertRaises(generation.DailyGenerationUnavailable):
                    reader()
                if add:
                    path.unlink()

    def test_actual_root_replacement_refuses_identical_bytes(self):
        reader = self.source()
        reader()
        previous = self.root / "previous-reviewed"
        self.assertEqual(self.producer.parent.resolve(), self.root.resolve())
        self.assertEqual(previous.parent.resolve(), self.root.resolve())
        self.producer.rename(previous)
        shutil.copytree(previous, self.producer)
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_source_root_changed"):
            reader()

    def test_changed_loaded_runtime_provenance_refuses_even_matching_files(self):
        reader = self.source()
        reader()
        with patch.object(cb, "verify_import_provenance",
                side_effect=generation.DailyGenerationUnavailable("daily_loaded_code_generation_mismatch")):
            with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "daily_loaded_code_generation_mismatch"):
                reader()

    def test_producer_mutation_during_runtime_read_cannot_publish_mixed_build(self):
        reader = self.source()
        original = reader._read_build
        def changed():
            value = original()
            (self.producer / "tests/windows/fixture.py").write_text("# mutation after first read\n")
            return value
        with patch.object(reader, "_read_build", side_effect=changed):
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_build_changed"):
                reader()

    def test_daily_files_outside_runtime_hash_are_bound_by_manifest(self):
        reader = self.source()
        reader()
        (self.runtime / "docs/agent-policy.md").write_text("# changed policy\n")
        with self.assertRaises(generation.DailyGenerationUnavailable):
            reader()

    def test_initializer_outside_inventory_is_refused(self):
        reader = self.source()
        reader()
        (self.producer / "tests/__init__.py").write_text("raise RuntimeError('never imported')\n")
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_fixture_layout_changed"):
            reader()

    def test_initializer_in_namespace_subdirectory_is_refused(self):
        (self.producer / "tests/windows/__init__.py").write_text("# unexpected\n")
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_fixture_layout_changed"):
            self.source()

    def test_original_root_identity_change_refuses(self):
        reader = self.source()
        reader()
        original = cb._identity
        with patch.object(cb, "_identity", side_effect=lambda p: (0, 999) if p == self.producer else original(p)):
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_source_root_changed"):
                reader()

    def test_wrong_digest_refuses_before_inventory(self):
        with patch.object(ce.CurrentBuildSource, "_inventory", side_effect=AssertionError("inventory before binding")):
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_source_generation_changed"):
                cb.SourceBoundBuildSource(replace(self.binding, source_digest="a" * 64))

    def test_noncanonical_runtime_and_malformed_binding_refused(self):
        cases = [self.binding.to_dict() | {"schema_version": True},
                 self.binding.to_dict() | {"kind": "arbitrary_files"},
                 self.binding.to_dict() | {"runtime_root": str(self.producer)},
                 self.binding.to_dict() | {"producer_root": "relative"},
                 self.binding.to_dict() | {"source_digest": "invalid"},
                 self.binding.to_dict() | {"extra": 1}]
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(ce.CapabilityEvidenceError):
                    cb.SourceBinding.from_dict(value)

    def test_redirected_root_component_refused(self):
        import stat
        from types import SimpleNamespace
        original = ce.os.lstat
        def redirected(path):
            return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400) if Path(path) == self.producer else original(path)
        with patch.object(ce.os, "lstat", side_effect=redirected):
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_path_unsafe"):
                cb.SourceBinding.from_dict(self.binding.to_dict())

    def test_reader_rejects_binding_replacement_and_wrong_exact_type(self):
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_source_binding_invalid"):
            cb.SourceBoundBuildSource(self.binding.to_dict())
        reader = self.source()
        reader.binding = replace(self.binding, source_digest="b" * 64)
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_source_binding_changed"):
            reader()

    def test_original_bounds_remain_effective(self):
        with patch.object(ce, "_MAX_BUILD_FILES", 1):
            with self.assertRaises(ce.CapabilityEvidenceError):
                self.source()()
        with patch.object(ce, "_MAX_BUILD_ENTRIES", 1):
            with self.assertRaises(ce.CapabilityEvidenceError):
                self.source()()
        with patch.object(ce, "_MAX_BUILD_BYTES", 1):
            with self.assertRaises(ce.CapabilityEvidenceError):
                self.source()()

    def bundle(self):
        # Reuse only explicit in-process synthetic host/profile/gate fixtures.
        fixture = fixtures.CapabilityEvidenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.bundle.update(schema_version=2, source_binding=self.binding.to_dict(),
                              build=asdict(self.source()()))
        fixture.data = {"S1": fixtures.s1_data()}
        return fixture

    def authority(self, fixture, **kwargs):
        return ce.NativeEvidenceAuthority(profile=fixture.profile, bundle_directory=fixture.path,
            expected_bundle_sha256=fixture.write(), live_context_source=lambda: fixture.context,
            clock=lambda: fixture.now, **kwargs)

    def test_v2_consumer_reads_actual_roots_and_still_refuses_missing_gates(self):
        fixture = self.bundle()
        authority = self.authority(fixture)
        result = authority.assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_required_gates_unverified")
        self.assertIs(type(authority.build_source), cb.SourceBoundBuildSource)
        self.assertEqual(result.missing_gates, ("S2", "S3", "P4"))

    def test_v2_consumer_refuses_build_callback(self):
        fixture = self.bundle()
        result = self.authority(fixture, build_source=lambda: self.source()()).assess()
        self.assertEqual(result.reason, "capability_bound_build_override_refused")

    def test_complete_synthetic_v2_uses_unchanged_reducers(self):
        fixture = self.bundle()
        complete = fixtures.CapabilityEvidenceTests()
        complete.setUp()
        self.addCleanup(complete.doCleanups)
        fixture.data = complete.data
        result = self.authority(fixture).assess()
        self.assertTrue(result.eligible, result)
        self.assertEqual(result.reason, "capability_evidence_verified")

    def test_v2_consumer_holds_on_failed_loaded_runtime_attestation(self):
        fixture = self.bundle()
        authority = self.authority(fixture)
        with patch.object(cb, "verify_import_provenance",
                side_effect=generation.DailyGenerationUnavailable("daily_loaded_code_generation_mismatch")):
            result = authority.assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_evidence_unavailable")

    def test_v2_refresh_refuses_later_build_callback(self):
        fixture = self.bundle()
        authority = self.authority(fixture)
        authority.assess()
        authority.build_source = lambda: self.source()()
        self.assertEqual(authority.refresh().reason, "capability_bound_build_override_refused")

    def test_v2_consumer_detects_actual_build_mismatch(self):
        fixture = self.bundle()
        fixture.bundle["build"]["producer_sha256"] = "f" * 64
        result = self.authority(fixture).assess()
        self.assertEqual(result.reason, "capability_build_mismatch")

    def test_v2_refresh_does_not_adopt_changed_source(self):
        fixture = self.bundle()
        authority = self.authority(fixture)
        authority.assess()
        (self.producer / "tests/fixtures/fixture.py").write_text("# changed\n")
        self.assertEqual(authority.refresh().reason, "capability_build_changed")

    def test_bundle_source_fields_closed_for_each_version(self):
        for version, extra in ((1, False), (2, True), (True, False), (3, False)):
            with self.subTest(version=version, extra=extra):
                fixture = self.bundle()
                fixture.bundle["schema_version"] = version
                if extra:
                    fixture.bundle["additional"] = "no"
                self.assertEqual(self.authority(fixture).assess().reason, "capability_schema_invalid")


if __name__ == "__main__":
    unittest.main()
