"""Isolated exact-source installer tests; native file ownership is synthetic."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "daily_source_install.py"
SPEC = importlib.util.spec_from_file_location("_daily_source_install_tests", SCRIPT)
install = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = install
SPEC.loader.exec_module(install)


class FixtureFile:
    def __init__(self, path, factory, *, created=False):
        self.path, self.factory, self.created = Path(path), factory, created
        self.backup_bytes = self.path.read_bytes()
        self.stat_identity = install._identity(self.path)
        self.closed = False

    def read_bytes(self):
        return self.path.read_bytes()

    def overwrite(self, data, *, expected_sha256):
        if install._hash(self.read_bytes()) != expected_sha256:
            raise install.SourceInstallRefused("synthetic_hash_changed")
        self.factory.writes.append((self.path, len(self.factory.owners)))
        if self.factory.fail_write:
            raise RuntimeError("synthetic unknown write")
        self.path.write_bytes(data)

    def delete_new(self, *, expected_sha256):
        if not self.created or install._hash(self.read_bytes()) != expected_sha256:
            raise RuntimeError("synthetic delete refused")
        self.path.unlink()

    def close(self):
        if self.factory.fail_close:
            raise RuntimeError("synthetic unknown close")
        self.closed = True


class FixtureFiles:
    def __init__(self, **kwargs):
        self.owners, self.writes = [], []
        self.fail_write = self.fail_close = False
        self.on_open = None

    def open_existing(self, path, *, expected_sha256):
        owner = FixtureFile(path, self)
        if install._hash(owner.backup_bytes) != expected_sha256:
            raise RuntimeError("synthetic changed source")
        self.owners.append(owner)
        if self.on_open:
            self.on_open(path)
        return owner

    def create_new(self, path):
        with Path(path).open("xb"):
            pass
        owner = FixtureFile(path, self, created=True)
        self.owners.append(owner)
        return owner

    def prepare_parent_directories(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        return SimpleNamespace(created_directories=(), close=lambda: None)


class DailySourceInstallTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.candidate, self.daily, self.data = (self.base / name for name in ("candidate", "daily", "data"))
        for root in (self.candidate, self.daily):
            for relative in install.REQUIRED:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"# exact fixture source\n")
        self.data.mkdir()
        self.config = self.data / "config.json"
        self.config.write_text(json.dumps({"admission_policy": "resource-v2", "local_allocatable_ram_gib": 58}))
        self.ledger = self.data / "sentinel.db"
        self.ledger.write_bytes(b"retained file identity fixture")
        self.preparation = self.base / "preparation.json"
        self.backup = self.base / "backup"
        self.location = patch.object(install, "daily_paths", return_value=(self.daily, self.data))
        self.location.start()
        self.addCleanup(self.location.stop)
        self.prepare()

    def prepare(self):
        paths = sorted(install._source_closure(self.candidate))
        self.manifest = {"schema_version": 1, "files": [{"path": relative,
            "sha256": install._hash((self.candidate / relative).read_bytes()),
            "size": (self.candidate / relative).stat().st_size} for relative in paths]}
        self.digest = install._hash(install._canonical(self.manifest))
        baseline = []
        for relative in paths:
            target = self.daily / relative
            row = {"path": relative, "existed": target.exists()}
            if row["existed"]:
                row.update(sha256=install._hash(target.read_bytes()), identity=install._identity(target))
            baseline.append(row)
        identity = self.ledger.stat()
        self.prepared = {"schema_version": 1, "purpose": "review_only_not_activation_authority",
            "daily_root": str(self.daily), "daily_data_dir": str(self.data),
            "ledger_path": str(self.ledger), "ledger_identity": [str(identity.st_dev), str(identity.st_ino)],
            "config_sha256": install._hash(self.config.read_bytes()), "candidate": self.manifest,
            "baseline": baseline, "unreviewed_daily_files": []}
        self.save()

    def save(self):
        self.preparation.write_text(json.dumps(self.prepared))

    def load(self, *, digest=None):
        return install.PreparedInstall.load(self.preparation, candidate_root=self.candidate,
            approved_digest=self.digest if digest is None else digest,
            approved_preparation_digest=install._hash(self.preparation.read_bytes()))

    def operation(self):
        self.factory = FixtureFiles()
        replacement = SimpleNamespace(NativeSourceFiles=lambda **kwargs: self.factory)
        for seam in (patch.dict(sys.modules, {"daily_source_handles": replacement}),
                     patch.object(install, "assert_no_sentinel_imports")):
            seam.start()
            self.addCleanup(seam.stop)
        return install.SourceInstallation(self.load(), self.backup)

    def change_candidate(self):
        self.relative = "sentinel/coordinator.py"
        (self.candidate / self.relative).write_bytes(b"# reviewed replacement\n")
        self.prepare()

    def test_review_creates_no_backup_or_runtime_change(self):
        baseline = self.ledger.read_bytes(), self.config.read_bytes()
        self.load()
        self.assertFalse(self.backup.exists())
        self.assertEqual(baseline, (self.ledger.read_bytes(), self.config.read_bytes()))

    def test_wrong_approved_digest_is_rejected(self):
        with self.assertRaisesRegex(install.SourceInstallRefused, "digest_mismatch"):
            self.load(digest="f" * 64)

    def test_preparation_change_after_approval_refuses(self):
        approved = install._hash(self.preparation.read_bytes())
        self.preparation.write_text(self.preparation.read_text() + " ")
        with self.assertRaisesRegex(install.SourceInstallRefused, "preparation_changed"):
            install.PreparedInstall.load(self.preparation, candidate_root=self.candidate,
                approved_digest=self.digest, approved_preparation_digest=approved)

    def test_later_user_edit_is_not_an_installable_baseline(self):
        path = self.daily / "sentinel/coordinator.py"
        path.write_bytes(b"# user's new work\n")
        with self.assertRaisesRegex(install.SourceInstallRefused, "baseline_changed"):
            self.load()
        self.assertIn(b"user's", path.read_bytes())

    def test_same_bytes_replacement_is_not_same_source_file(self):
        path = self.daily / "sentinel/coordinator.py"
        replacement = self.daily / "replacement.tmp"
        replacement.write_bytes(path.read_bytes())
        replacement.replace(path)
        with self.assertRaisesRegex(install.SourceInstallRefused, "baseline_changed"):
            self.load()

    def test_same_bytes_ledger_replacement_refuses(self):
        replacement = self.data / "replacement.db"
        replacement.write_bytes(self.ledger.read_bytes())
        replacement.replace(self.ledger)
        with self.assertRaisesRegex(install.SourceInstallRefused, "ledger_changed"):
            self.load()

    def test_missing_prepared_ledger_identity_refuses(self):
        self.prepared.pop("ledger_identity")
        self.save()
        with self.assertRaisesRegex(install.SourceInstallRefused, "ledger_binding_required"):
            self.load()

    def test_changed_config_refuses_without_rewriting(self):
        self.config.write_text(self.config.read_text() + " ")
        with self.assertRaisesRegex(install.SourceInstallRefused, "config_changed"):
            self.load()

    def test_fixed_policy_mismatch_refuses_even_with_new_hash(self):
        self.config.write_text(json.dumps({"admission_policy": "resource-v2", "local_allocatable_ram_gib": 59}))
        self.prepare()
        with self.assertRaisesRegex(install.SourceInstallRefused, "fixed_policy_mismatch"):
            self.load()

    def test_additional_daily_source_refuses(self):
        (self.daily / "scripts/unreviewed.py").write_bytes(b"# user's additional source")
        with self.assertRaisesRegex(install.SourceInstallRefused, "closure_changed"):
            self.load()

    def test_candidate_change_after_review_refuses(self):
        (self.candidate / "sentinel/coordinator.py").write_bytes(b"# changed candidate")
        with self.assertRaisesRegex(install.SourceInstallRefused, "candidate_changed"):
            self.load()

    def test_manifest_cannot_name_configuration(self):
        with self.assertRaisesRegex(install.SourceInstallRefused, "outside_source"):
            install._relative("config.json")

    def test_manifest_cannot_escape_source(self):
        with self.assertRaisesRegex(install.SourceInstallRefused, "path_invalid"):
            install._relative("../outside.py")

    def test_duplicate_preparation_keys_refuse(self):
        self.preparation.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaisesRegex(install.SourceInstallRefused, "duplicate_key"):
            self.load()

    def test_loaded_sentinel_process_cannot_apply(self):
        with patch.dict(sys.modules, {"sentinel": object()}), \
                self.assertRaisesRegex(install.SourceInstallRefused, "unimported_process"):
            install.assert_no_sentinel_imports()

    def test_all_existing_files_are_held_before_first_write(self):
        self.change_candidate()
        operation = self.operation()
        operation.apply()
        self.assertEqual(len(self.factory.writes), 1)
        self.assertEqual(self.factory.writes[0][1], len(self.prepared["baseline"]))
        self.assertTrue(operation.source_complete)
        self.assertTrue(operation.settled)
        self.assertFalse(operation.runtime_started)
        self.assertTrue(all(owner.closed for owner in self.factory.owners))

    def test_backup_retains_exact_original_bytes(self):
        self.change_candidate()
        original = (self.daily / self.relative).read_bytes()
        operation = self.operation()
        operation.apply()
        self.assertEqual((self.backup / self.relative).read_bytes(), original)
        self.assertEqual((self.daily / self.relative).read_bytes(), (self.candidate / self.relative).read_bytes())

    def test_unchanged_source_is_not_overwritten(self):
        operation = self.operation()
        operation.apply()
        self.assertEqual(self.factory.writes, [])
        self.assertEqual(operation.written, [])

    def test_existing_backup_is_not_reused(self):
        operation = self.operation()
        self.backup.mkdir()
        with self.assertRaisesRegex(install.SourceInstallRefused, "backup_already_exists"):
            operation.apply()
        self.assertEqual(self.factory.owners, [])

    def test_changed_file_after_acquisition_aborts_before_write(self):
        self.change_candidate()
        operation = self.operation()
        def changed(path):
            if path == self.daily / self.relative:
                path.write_bytes(b"# changed during synthetic acquisition")
        self.factory.on_open = changed
        with self.assertRaisesRegex(install.SourceInstallRefused, "baseline_changed"):
            operation.apply()
        self.assertEqual(self.factory.writes, [])
        self.assertFalse(operation.source_complete)

    def test_unknown_write_retains_original_operation(self):
        self.change_candidate()
        operation = self.operation()
        self.factory.fail_write = True
        with self.assertRaisesRegex(RuntimeError, "unknown write") as failed:
            operation.apply()
        self.assertIs(failed.exception.source_installation, operation)
        self.assertEqual(operation.written, [self.relative])
        self.assertFalse(operation.settled)
        self.assertFalse(any(owner.closed for owner in self.factory.owners))

    def test_new_file_creation_is_retained_before_first_write(self):
        relative = "sentinel/new-directory/extra.py"
        path = self.candidate / relative
        path.parent.mkdir(parents=True)
        path.write_bytes(b"# new reviewed source")
        self.prepare()
        operation = self.operation()
        self.factory.fail_write = True
        with self.assertRaisesRegex(RuntimeError, "unknown write"):
            operation.apply()
        self.assertTrue(operation.source_mutation_attempted)
        self.assertTrue((self.daily / relative).exists())
        self.assertEqual(operation.written, [relative])
        with self.assertRaisesRegex(install.SourceInstallRefused, "mutation_custody_required"):
            operation.release_without_source_mutation()

    def test_unknown_close_cannot_claim_source_settled(self):
        operation = self.operation()
        self.factory.fail_close = True
        with self.assertRaisesRegex(RuntimeError, "unknown close"):
            operation.apply()
        self.assertTrue(operation.source_complete)
        self.assertFalse(operation.settled)

    def test_runtime_start_prohibits_source_rollback(self):
        operation = self.operation()
        operation.runtime_started = True
        with self.assertRaisesRegex(install.SourceInstallRefused, "runtime_obligations"):
            operation.rollback_source_before_runtime()

    def test_unsettled_source_cannot_import_daily_host(self):
        operation = self.operation()
        with self.assertRaisesRegex(install.SourceInstallRefused, "source_unsettled"):
            operation.enter_daily_host()
        self.assertFalse(operation.runtime_started)

    def test_prewrite_refusal_can_release_exact_file_owners(self):
        operation = self.operation()
        operation.owners = {"one": self.factory.open_existing(self.daily / "sentinel/coordinator.py",
            expected_sha256=install._hash((self.daily / "sentinel/coordinator.py").read_bytes()))}
        operation.release_without_source_mutation()
        self.assertTrue(operation.settled)
        self.assertTrue(self.factory.owners[0].closed)

    def _assert_cli_source_interruption_custody(self, reporting_error=None):
        cli_spec = importlib.util.spec_from_file_location("_daily_activate_cli_tests",
            SCRIPT.with_name("adaptive-activate.py"))
        cli = importlib.util.module_from_spec(cli_spec)
        with patch.dict(sys.modules, {"daily_source_install": install}):
            cli_spec.loader.exec_module(cli)
        self.change_candidate()
        plan = self.load()
        operation = install.SourceInstallation(plan, self.backup)
        def interrupted():
            operation.source_mutation_attempted = True
            operation.written.append(self.relative)
            raise SystemExit(17)
        class CustodyObserved(BaseException):
            pass
        argv = ["--private-preparation", str(self.preparation), "--manifest-sha256", self.digest,
                "--preparation-sha256", install._hash(self.preparation.read_bytes()),
                "--backup-directory", str(self.backup), "--apply-daily-accounting-handoff"]
        with patch.object(cli, "assert_no_sentinel_imports"), \
                patch.object(cli.PreparedInstall, "load", return_value=plan), \
                patch.object(cli, "SourceInstallation", return_value=operation), \
                patch.object(operation, "apply", side_effect=interrupted), \
                patch.object(cli, "remain_with_source_custody", side_effect=CustodyObserved) as keeper, \
                patch("builtins.print", side_effect=reporting_error), self.assertRaises(CustodyObserved):
            cli.main(argv)
        keeper.assert_called_once_with(operation)

    def test_system_exit_after_source_mutation_retains_same_operation(self):
        self._assert_cli_source_interruption_custody()

    def test_broken_diagnostics_cannot_discard_source_mutation_custody(self):
        self._assert_cli_source_interruption_custody(BrokenPipeError("synthetic lost stdout"))


if __name__ == "__main__":
    unittest.main()
