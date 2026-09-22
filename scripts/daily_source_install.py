"""Explicit source installation before any Sentinel package is imported.

This module uses only the standard library and the retained Windows file owner
beside it. Review data never grants admission. The caller must separately opt
in to applying the exact reviewed digest, and then remain the original daily
activation/supervisor process. No configuration or Scheduled Task is written.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import time


MAX_JSON = 1024 * 1024
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 1024
REQUIRED = frozenset({
    "sentinel_daily_bootstrap.py", "sentinel/__init__.py", "sentinel/coordinator.py",
    "sentinel/maintainer.py", "sentinel/accounting.py", "sentinel/orchestrator.py",
    "sentinel/adaptive/store.py", "sentinel/adaptive/writers.py",
    "sentinel/adaptive/legacy_writer.py", "sentinel/adaptive/daily_generation.py",
    "scripts/sentinelctl.py", "scripts/maintainerctl.py", "scripts/invoke-sentinel.ps1",
    "scripts/collect.ps1", "scripts/collect-scheduled.ps1", "scripts/legacy-mutation.py",
    "hooks/sentinel-gate.py", "hooks/sentinel-stop.py", "docs/agent-policy.md",
})


class SourceInstallRefused(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _reject(reason):
    raise SourceInstallRefused(reason)


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _strict_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _reject("daily_preparation_duplicate_key")
        value[key] = item
    return value


def _read(path, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        _reject("daily_install_input_bound_exceeded")
    return data


def _read_json(path):
    return json.loads(_read(path, MAX_JSON).decode("utf-8-sig"), object_pairs_hook=_strict_pairs,
                      parse_constant=lambda value: _reject("daily_install_invalid_json"))


def _plain_path(path, *, existing=True):
    path = Path(path).absolute()
    if len(path.parts) > 128:
        _reject("daily_install_path_bound_exceeded")
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            if existing or item != path:
                raise
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            _reject("daily_install_reparse_unsupported")
    return path.resolve(strict=existing)


def _relative(value):
    if type(value) is not str or not 0 < len(value) <= 512:
        _reject("daily_install_path_invalid")
    part = PurePosixPath(value)
    if (part.is_absolute() or ".." in part.parts or str(part) != value or
            "\\" in value or ":" in value):
        _reject("daily_install_path_invalid")
    allowed = value in {"sentinel_daily_bootstrap.py", "docs/agent-policy.md"}
    allowed = allowed or (len(part.parts) >= 2 and part.parts[0] in {"sentinel", "scripts", "hooks"}
                          and part.suffix.casefold() in {".py", ".ps1"})
    if not allowed:
        _reject("daily_install_path_outside_source")
    return value


def _source_closure(root):
    found = set()
    for folder in ("sentinel", "scripts", "hooks"):
        directory = root / folder
        if not directory.is_dir():
            _reject("daily_install_source_closure_incomplete")
        for path in directory.rglob("*"):
            _plain_path(path)
            if path.is_file() and path.suffix.casefold() in {".py", ".ps1"}:
                found.add(path.relative_to(root).as_posix())
                if len(found) > MAX_FILES:
                    _reject("daily_install_source_bound_exceeded")
    for relative in ("sentinel_daily_bootstrap.py", "docs/agent-policy.md"):
        if (root / relative).is_file():
            _plain_path(root / relative)
            found.add(relative)
    return found


def _identity(path):
    info = path.stat()
    return {"device": info.st_dev, "file_id": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def daily_paths():
    home = Path.home().resolve()
    return home / "Projects" / "resource-sentinel", home / ".resource-sentinel"


def assert_no_sentinel_imports():
    if any(name == "sentinel" or name.startswith("sentinel.") or name == "sentinel_daily_bootstrap"
           for name in tuple(sys.modules)):
        _reject("daily_install_requires_unimported_process")


@dataclass(frozen=True)
class PreparedInstall:
    candidate_root: Path
    daily_root: Path
    data_dir: Path
    manifest: dict
    digest: str
    preparation_digest: str
    baseline: tuple
    source_bytes: dict
    config_digest: str
    ledger_identity: tuple

    @classmethod
    def load(cls, preparation, *, candidate_root, approved_digest, approved_preparation_digest):
        if not _digest(approved_digest) or not _digest(approved_preparation_digest):
            _reject("daily_install_exact_digest_required")
        raw = _read(preparation, MAX_JSON)
        if _hash(raw) != approved_preparation_digest:
            _reject("daily_install_preparation_changed")
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_strict_pairs,
                           parse_constant=lambda value: _reject("daily_install_invalid_json"))
        if (type(value) is not dict or value.get("schema_version") != 1 or
                value.get("purpose") != "review_only_not_activation_authority"):
            _reject("daily_preparation_invalid")
        root, data = daily_paths()
        root, data = _plain_path(root), _plain_path(data)
        if (Path(value["daily_root"]).resolve() != root or Path(value["daily_data_dir"]).resolve() != data or
                Path(value["ledger_path"]).resolve() != data / "sentinel.db"):
            _reject("daily_install_location_mismatch")
        if value.get("unreviewed_daily_files") != []:
            _reject("daily_install_unreviewed_source")
        manifest = value["candidate"]
        if (type(manifest) is not dict or set(manifest) != {"schema_version", "files"} or
                type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or
                type(manifest["files"]) is not list or not 0 < len(manifest["files"]) <= MAX_FILES):
            _reject("daily_install_manifest_invalid")
        if _hash(_canonical(manifest)) != approved_digest:
            _reject("daily_install_digest_mismatch")
        rows = manifest["files"]
        for row in rows:
            if (type(row) is not dict or set(row) != {"path", "sha256", "size"} or
                    not _digest(row["sha256"]) or type(row["size"]) is not int or
                    not 0 <= row["size"] <= MAX_FILE):
                _reject("daily_install_manifest_invalid")
            _relative(row["path"])
        paths = [row["path"] for row in rows]
        if paths != sorted(set(paths)) or not REQUIRED <= set(paths) or sum(row["size"] for row in rows) > MAX_TOTAL:
            _reject("daily_install_manifest_invalid")
        candidate = _plain_path(candidate_root)
        if candidate == root or _source_closure(candidate) != set(paths):
            _reject("daily_install_candidate_closure_mismatch")
        source_bytes = {}
        for row in rows:
            content = _read(_plain_path(candidate / row["path"]), MAX_FILE)
            if len(content) != row["size"] or _hash(content) != row["sha256"]:
                _reject("daily_install_candidate_changed")
            source_bytes[row["path"]] = content
        baseline = value["baseline"]
        if type(baseline) is not list or [row.get("path") for row in baseline] != paths:
            _reject("daily_preparation_invalid")
        for row in baseline:
            fields = {"path", "existed", "sha256", "identity"} if row.get("existed") is True else {"path", "existed"}
            if type(row) is not dict or set(row) != fields or type(row["existed"]) is not bool:
                _reject("daily_preparation_invalid")
            if row["existed"]:
                if (not _digest(row["sha256"]) or type(row["identity"]) is not dict or
                        set(row["identity"]) != {"device", "file_id", "size", "mtime_ns"} or
                        any(type(item) is not int or item < 0 for item in row["identity"].values())):
                    _reject("daily_preparation_invalid")
        identity = value.get("ledger_identity")
        if (type(identity) is not list or len(identity) != 2 or
                any(type(item) is not str or not item.isascii() or not item.isdecimal() or len(item) > 39
                    for item in identity)):
            _reject("daily_install_ledger_binding_required")
        if not _digest(value["config_sha256"]):
            _reject("daily_preparation_invalid")
        result = cls(candidate, root, data, manifest, approved_digest, approved_preparation_digest, tuple(baseline), source_bytes,
                     value["config_sha256"], tuple(int(item) for item in identity))
        result.assert_protected_baseline()
        return result

    def assert_config_ledger(self):
        config_path = _plain_path(self.data_dir / "config.json")
        raw = _read(config_path, MAX_JSON)
        if _hash(raw) != self.config_digest:
            _reject("daily_install_config_changed")
        config = json.loads(raw.decode("utf-8-sig"))
        if (config.get("admission_policy") != "resource-v2" or config.get("local_allocatable_ram_gib") != 58 or
                config.get("local_physical_headroom_gib", 4) != 4 or config.get("local_commit_headroom_gib", 4) != 4):
            _reject("daily_install_fixed_policy_mismatch")
        path = _plain_path(self.data_dir / "sentinel.db")
        value = path.stat()
        if not stat.S_ISREG(value.st_mode) or (value.st_dev, value.st_ino) != self.ledger_identity:
            _reject("daily_install_ledger_changed")

    def assert_protected_baseline(self):
        self.assert_config_ledger()
        expected = {row["path"] for row in self.baseline if row["existed"]}
        if _source_closure(self.daily_root) != expected:
            _reject("daily_install_baseline_closure_changed")
        for row in self.baseline:
            path = self.daily_root / row["path"]
            if not row["existed"]:
                if path.exists():
                    _reject("daily_install_baseline_changed")
                continue
            _plain_path(path)
            if _identity(path) != row["identity"] or _hash(_read(path, MAX_FILE)) != row["sha256"]:
                _reject("daily_install_baseline_changed")


class SourceInstallation:
    """Own exact target handles until source and cleanup positively settle."""

    def __init__(self, plan, backup_directory):
        if type(plan) is not PreparedInstall:
            _reject("daily_install_preparation_required")
        self.plan = plan
        self.backup_directory = Path(backup_directory).absolute()
        self.owners = {}
        self.parent_owners = []
        self.written = []
        self.errors = []
        self.source_complete = False
        self.settled = False
        self.runtime_started = False
        self.source_mutation_attempted = False

    def apply(self):
        assert_no_sentinel_imports()
        from daily_source_handles import NativeSourceFiles
        self.plan.assert_protected_baseline()
        if self.backup_directory.exists():
            _reject("daily_install_backup_already_exists")
        _plain_path(self.backup_directory.parent)
        if self.backup_directory == self.plan.daily_root or self.plan.daily_root in self.backup_directory.parents:
            _reject("daily_install_backup_inside_source")
        self.backup_directory.mkdir()
        self._write_report("acquiring_source")
        files = NativeSourceFiles(max_bytes=MAX_FILE)
        try:
            # Hold every existing manifest member, including unchanged source,
            # before the first source mutation. No concurrent writer can alter
            # the checked bytes while these exact handles remain retained.
            for row in self.plan.baseline:
                if row["existed"]:
                    owner = files.open_existing(self.plan.daily_root / row["path"], expected_sha256=row["sha256"])
                    self.owners[row["path"]] = owner
                    if owner.stat_identity != row["identity"]:
                        _reject("daily_install_baseline_changed")
            self.plan.assert_protected_baseline()
            for row in self.plan.baseline:
                if row["existed"] and self.owners[row["path"]].backup_bytes != self.plan.source_bytes[row["path"]]:
                    destination = self.backup_directory / row["path"]
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with destination.open("xb") as stream:
                        stream.write(self.owners[row["path"]].backup_bytes)
                        stream.flush()
                        os.fsync(stream.fileno())
            self._write_report("backups_complete")
            for row in self.plan.baseline:
                relative = row["path"]
                data = self.plan.source_bytes[relative]
                if row["existed"] and data == self.owners[relative].backup_bytes:
                    continue
                if not row["existed"]:
                    target = self.plan.daily_root / relative
                    self.source_mutation_attempted = True
                    parents = files.prepare_parent_directories(target)
                    self.parent_owners.append(parents)
                    self.owners[relative] = files.create_new(target)
                owner = self.owners[relative]
                # Retain this mutation before it can lose its acknowledgement.
                self.source_mutation_attempted = True
                self.written.append(relative)
                owner.overwrite(data, expected_sha256=row.get("sha256", _hash(b"")))
                self._write_report("writing_source")
            self.plan.assert_config_ledger()
            if _source_closure(self.plan.daily_root) != set(self.plan.source_bytes):
                _reject("daily_install_postwrite_closure_changed")
            for path, owner in self.owners.items():
                if owner.read_bytes() != self.plan.source_bytes[path]:
                    _reject("daily_install_postwrite_mismatch")
            self.source_complete = True
            self._write_report("source_verified")
        except BaseException as error:
            self.errors.append(error)
            retained = getattr(error, "retained_file", None)
            directories = getattr(error, "retained_directories", None)
            if directories is not None and directories not in self.parent_owners:
                self.parent_owners.append(directories)
            elif retained is not None and retained not in self.owners.values():
                self.owners["<unsettled-acquisition>"] = retained
            error.source_installation = self
            self._write_report("source_incomplete")
            raise
        self.close_source_handles()
        self._write_report("source_settled_runtime_not_started")

    def close_source_handles(self):
        if not self.source_complete:
            _reject("daily_install_source_not_verified")
        for owner in self.owners.values():
            owner.close()
        for owner in reversed(self.parent_owners):
            owner.close()
        self.settled = True

    def release_without_source_mutation(self):
        if self.source_mutation_attempted or self.written or self.runtime_started:
            _reject("daily_install_mutation_custody_required")
        for owner in self.owners.values():
            owner.close()
        self.settled = True

    def _write_report(self, state):
        # Local evidence contains paths; never send its contents to public logs.
        record = {"schema_version": 1, "state": state, "manifest_sha256": self.plan.digest,
                  "preparation_sha256": self.plan.preparation_digest,
                  "daily_root": str(self.plan.daily_root), "written": list(self.written),
                  "source_complete": self.source_complete, "source_handles_settled": self.settled,
                  "source_mutation_attempted": self.source_mutation_attempted,
                  "created_directories": [path for owner in self.parent_owners for path in owner.created_directories],
                  "runtime_started": self.runtime_started,
                  "errors": [getattr(error, "reason", type(error).__name__) for error in self.errors]}
        try:
            with (self.backup_directory / "operation.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException as error:
            self.errors.append(error)
            error.source_installation = self
            raise

    def rollback_source_before_runtime(self):
        if self.runtime_started:
            _reject("daily_install_runtime_obligations_prohibit_source_rollback")
        originals = {row["path"]: row for row in self.plan.baseline}
        for relative in reversed(self.written):
            row, owner = originals[relative], self.owners[relative]
            installed = _hash(self.plan.source_bytes[relative])
            if row["existed"]:
                owner.overwrite(owner.backup_bytes, expected_sha256=installed)
            else:
                owner.delete_new(expected_sha256=installed)
        # A deletion-pending result is not proof the new path is absent.
        # Leave custody resident for explicit reconciliation; never claim that
        # closed handles or an elapsed interval completed rollback.
        self._write_report("source_rollback_requires_reconciliation")

    def enter_daily_host(self):
        if not self.source_complete or not self.settled:
            _reject("daily_install_source_unsettled")
        assert_no_sentinel_imports()
        self.plan.assert_config_ledger()
        # The interpreter that acquired the source owners becomes the actual
        # canonical daily supervisor; no subprocess/PID reconstruction occurs.
        sys.path[:] = [value for value in sys.path if Path(value or os.getcwd()).resolve() not in
                       {self.plan.candidate_root, self.plan.candidate_root / "scripts"}]
        sys.path.insert(0, str(self.plan.daily_root))
        self.runtime_started = True
        self._write_report("canonical_runtime_import_started")
        from sentinel.adaptive.daily_generation import SourceManifest
        from sentinel.adaptive.daily_activation_host import DailyActivationHost
        from sentinel.adaptive.daily_readiness_transport import LedgerFileIdentity
        host = DailyActivationHost(SourceManifest.from_dict(self.plan.manifest),
            expected_config_digest=self.plan.config_digest,
            expected_ledger_identity=LedgerFileIdentity(*self.plan.ledger_identity))
        self.host = host
        host.run_forever()


def _source_custody_tick(operation):
    """One retained iteration; broken diagnostics cannot skip pacing."""
    try:
        print(json.dumps({"event": "daily_source_custody_retained", "source_complete": operation.source_complete,
                          "written_files": len(operation.written), "activation_complete": False}), flush=True)
    except BaseException as error:
        # These fixed diagnostic boundaries retain only their first failure.
        # Repeated broken stdout must neither grow an error list nor spin.
        if getattr(operation, "keeper_reporting_error", None) is None:
            operation.keeper_reporting_error = error
    try:
        time.sleep(30)
    except BaseException as error:
        if getattr(operation, "keeper_pacing_error", None) is None:
            operation.keeper_pacing_error = error


def remain_with_source_custody(operation):
    """Report an unresolved source owner without silently discarding handles."""
    while True:
        # Explicit operator recovery must reconcile the exact operation;
        # Ctrl+C is not positive write/close acknowledgement.
        _source_custody_tick(operation)
