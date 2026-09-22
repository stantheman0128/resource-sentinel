"""Private baseline protection and read-only admission prerequisite reports."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_prerequisites as prerequisite
from sentinel.adaptive.daily_generation import DailyGenerationUnavailable, REQUIRED_PATHS


class DailyPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.candidate, self.daily, self.data = (self.base / name for name in ("candidate", "daily", "data"))
        for root in (self.candidate, self.daily):
            for relative in REQUIRED_PATHS:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# fixture\n")
        self.data.mkdir()
        self.config = self.data / "config.json"
        self.config.write_text(json.dumps({"admission_policy": "resource-v2", "local_allocatable_ram_gib": 58,
                                          "reservation_grace_sec": 120, "private_secret": "never print me"}))
        conn = sqlite3.connect(self.data / "sentinel.db")
        conn.executescript("CREATE TABLE reservations(id TEXT); CREATE TABLE worker_reservations(id TEXT); "
                           "CREATE TABLE queue(id TEXT);")
        conn.close()
        self.location = patch.object(prerequisite, "default_daily_paths", return_value=(self.daily, self.data))
        self.location.start()
        self.addCleanup(self.location.stop)

    def inspect(self):
        return prerequisite.inspect_daily(candidate_root=self.candidate)

    def test_matching_files_are_not_loaded_runtime_authority(self):
        public, _ = self.inspect()
        self.assertEqual(public["status"], "blocked")
        self.assertFalse(public["control_eligible"])
        self.assertIn("daily_retained_cohort_authority_required", public["blockers"])
        self.assertIn("daily_lifetime_schema_absent", public["blockers"])
        self.assertEqual(public["mutations"], 0)

    def test_inspector_preserves_database_and_configuration(self):
        db = self.data / "sentinel.db"
        before = db.read_bytes(), self.config.read_bytes()
        self.inspect()
        self.assertEqual(before, (db.read_bytes(), self.config.read_bytes()))
        self.assertFalse((self.data / "sentinel.db-journal").exists())

    def test_public_report_omits_private_paths_and_config(self):
        public, private = self.inspect()
        output = json.dumps(public)
        self.assertNotIn(str(self.base), output)
        self.assertNotIn("never print me", output)
        self.assertEqual(private["purpose"], "review_only_not_activation_authority")

    def test_alternate_data_directory_rejected_without_creation(self):
        other = self.base / "alternate"
        with self.assertRaisesRegex(DailyGenerationUnavailable, "location_mismatch"):
            prerequisite.inspect_daily(candidate_root=self.candidate, daily_data_dir=other)
        self.assertFalse(other.exists())

    def test_missing_database_not_created(self):
        (self.data / "sentinel.db").unlink()
        public, _ = self.inspect()
        self.assertIn("daily_ledger_unavailable_or_incompatible", public["blockers"])
        self.assertFalse((self.data / "sentinel.db").exists())

    def test_source_diff_and_missing_module_reported(self):
        (self.daily / "sentinel/coordinator.py").write_text("# pre-existing user change\n")
        (self.daily / "sentinel/adaptive/daily_generation.py").unlink()
        public, _ = self.inspect()
        self.assertEqual(public["source"]["changed_files"], 1)
        self.assertEqual(public["source"]["missing_files"], 1)
        self.assertIn("daily_source_not_candidate_generation", public["blockers"])

    def test_extra_daily_entrypoint_requires_review(self):
        (self.daily / "scripts/unreviewed.py").write_text("# untouched\n")
        public, private = self.inspect()
        self.assertEqual(public["source"]["unreviewed_daily_files"], 1)
        self.assertEqual(private["unreviewed_daily_files"], ["scripts/unreviewed.py"])

    def test_existing_queue_requires_drain_not_automatic_cancel(self):
        conn = sqlite3.connect(self.data / "sentinel.db")
        conn.execute("INSERT INTO queue VALUES('private-request')")
        conn.commit()
        conn.close()
        public, _ = self.inspect()
        self.assertEqual(public["ledger_counts"]["queue"], 1)
        self.assertIn("daily_existing_allocations_or_queue_require_drain", public["blockers"])

    def test_fixed_policy_mismatch_refuses_without_rewriting(self):
        self.config.write_text(json.dumps({"admission_policy": "resource-v2", "local_allocatable_ram_gib": 99}))
        before = self.config.read_bytes()
        public, _ = self.inspect()
        self.assertIn("daily_fixed_policy_mismatch", public["blockers"])
        self.assertEqual(self.config.read_bytes(), before)

    def test_baseline_roundtrip_has_no_install_side_effect(self):
        _, private = self.inspect()
        self.assertIsNone(prerequisite.validate_prepared_baseline(private))

    def test_changed_dirty_baseline_is_never_overwritten(self):
        _, private = self.inspect()
        path = self.daily / "sentinel/coordinator.py"
        path.write_text("# another agent's later edit\n")
        with self.assertRaisesRegex(DailyGenerationUnavailable, "baseline_changed"):
            prerequisite.validate_prepared_baseline(private)
        self.assertIn("later edit", path.read_text())

    def test_missing_target_created_after_prepare_stops_install(self):
        path = self.daily / "sentinel/adaptive/daily_generation.py"
        path.unlink()
        _, private = self.inspect()
        path.write_text("# new user file\n")
        with self.assertRaisesRegex(DailyGenerationUnavailable, "baseline_changed"):
            prerequisite.validate_prepared_baseline(private)

    def test_config_change_stops_install_even_when_source_unchanged(self):
        _, private = self.inspect()
        self.config.write_text(self.config.read_text() + " ")
        with self.assertRaisesRegex(DailyGenerationUnavailable, "config_changed"):
            prerequisite.validate_prepared_baseline(private)

    def test_new_entrypoint_after_preparation_is_not_ignored(self):
        _, private = self.inspect()
        (self.daily / "scripts/late.py").write_text("pass\n")
        with self.assertRaisesRegex(DailyGenerationUnavailable, "closure_changed"):
            prerequisite.validate_prepared_baseline(private)

    def test_extra_daily_source_never_gets_baseline_unchanged_verdict(self):
        path = self.daily / "scripts/unreviewed.py"
        path.write_text("# original\n")
        _, private = self.inspect()
        path.write_text("# later change\n")
        with self.assertRaisesRegex(DailyGenerationUnavailable, "unreviewed_source_requires_review"):
            prerequisite.validate_prepared_baseline(private)

    def test_oversized_config_has_bounded_read_and_refuses(self):
        self.config.write_bytes(b" " * (prerequisite.MAX_JSON + 1))
        with self.assertRaisesRegex(DailyGenerationUnavailable, "config_unavailable"):
            self.inspect()


if __name__ == "__main__":
    unittest.main()
