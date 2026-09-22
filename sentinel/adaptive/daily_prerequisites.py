"""Bounded, read-only daily provider inspection and private preparation.

This module deliberately imports no capacity constructor or native controller.
It does not repair a ledger, install a generation, issue an exemption, or treat
matching files/schema as evidence that old loaded consumers have retired.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3

from .daily_generation import (
    DailyGenerationUnavailable, SourceManifest, _existing_root, _read_source,
    _source_paths, read_generation,
)

MAX_JSON = 1024 * 1024


def default_daily_paths():
    # User-controlled environment overrides are not alternate ledger authority.
    home = Path.home().resolve()
    return home / "Projects" / "resource-sentinel", home / ".resource-sentinel"


def _read_json(path):
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_JSON + 1)
        if len(data) > MAX_JSON:
            raise ValueError
        value = json.loads(data.decode("utf-8-sig"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if type(value) is not dict:
            raise ValueError
        return value, hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, UnicodeError):
        raise DailyGenerationUnavailable("daily_config_unavailable") from None


def _snapshot_identity(path):
    info = path.stat()
    return {"device": info.st_dev, "file_id": info.st_ino,
            "size": info.st_size, "mtime_ns": info.st_mtime_ns}


def inspect_daily(*, candidate_root, daily_root=None, daily_data_dir=None):
    """Return public statistics and a separate private exact preparation record.

    Explicit paths must resolve to this user's existing daily locations. This
    is not an admission entrypoint and never returns control_eligible=True.
    Tests patch the home locator to isolated fixtures; there is no CLI bypass.
    """
    expected_root, expected_data = default_daily_paths()
    daily_root = Path(expected_root if daily_root is None else daily_root).resolve()
    daily_data = Path(expected_data if daily_data_dir is None else daily_data_dir).resolve()
    if daily_root != expected_root.resolve() or daily_data != expected_data.resolve():
        raise DailyGenerationUnavailable("daily_location_mismatch")
    root = _existing_root(daily_root)
    candidate = SourceManifest.capture(candidate_root)
    existing = set(_source_paths(root, require_complete=False))
    originals, changed, missing = [], [], []
    for entry in candidate.entries:
        if entry.path not in existing or not (root / entry.path).is_file():
            missing.append(entry.path)
            originals.append({"path": entry.path, "existed": False})
            continue
        data = _read_source(root, entry.path)
        digest = hashlib.sha256(data).hexdigest()
        originals.append({"path": entry.path, "existed": True, "sha256": digest,
                          "identity": _snapshot_identity(root / entry.path)})
        if digest != entry.sha256:
            changed.append(entry.path)
    additional = sorted(existing - {e.path for e in candidate.entries})
    config, config_hash = _read_json(daily_data / "config.json")
    blockers = []
    if changed or missing or additional:
        blockers.append("daily_source_not_candidate_generation")
    selected = {
        "admission_policy": config.get("admission_policy"),
        "ram_budget_gib": config.get("local_allocatable_ram_gib"),
        "physical_reserve_gib": config.get("local_physical_headroom_gib", 4),
        "commit_reserve_gib": config.get("local_commit_headroom_gib", 4),
        "reservation_grace_sec": config.get("reservation_grace_sec", 120),
    }
    if (selected["admission_policy"] != "resource-v2" or selected["ram_budget_gib"] != 58 or
            selected["physical_reserve_gib"] != 4 or selected["commit_reserve_gib"] != 4):
        blockers.append("daily_fixed_policy_mismatch")
    ledger = daily_data / "sentinel.db"
    counts = {}
    generation = None
    conn = None
    try:
        if not ledger.is_file():
            raise FileNotFoundError
        conn = sqlite3.connect(ledger.as_uri() + "?mode=ro", uri=True, timeout=.25)
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for name in ("reservations", "worker_reservations", "queue", "managed_executions"):
            counts[name] = conn.execute(f"SELECT count(*) FROM {name}").fetchone()[0] if name in tables else None
        generation = read_generation(conn)
        if generation is None:
            blockers.append("daily_generation_not_activated")
        elif generation["state"] != "ACTIVE":
            blockers.append("daily_generation_draining")
        if "managed_executions" not in tables:
            blockers.append("daily_lifetime_schema_absent")
    except (OSError, sqlite3.Error, DailyGenerationUnavailable):
        blockers.append("daily_ledger_unavailable_or_incompatible")
    finally:
        if conn is not None:
            conn.close()
    # Even a matching ACTIVE record cannot certify the native original owner.
    blockers.append("daily_retained_cohort_authority_required")
    if any(value for name, value in counts.items() if name != "managed_executions"):
        blockers.append("daily_existing_allocations_or_queue_require_drain")
    public = {
        "schema_version": 1, "status": "blocked", "control_eligible": False,
        "mutations": 0, "candidate_source_sha256": candidate.digest,
        "source": {"candidate_files": len(candidate.entries), "changed_files": len(changed),
                   "missing_files": len(missing), "unreviewed_daily_files": len(additional)},
        "policy": selected, "ledger_counts": counts,
        "generation_present": generation is not None,
        "blockers": sorted(set(blockers)),
    }
    private = {
        "schema_version": 1, "purpose": "review_only_not_activation_authority",
        "daily_root": str(root), "daily_data_dir": str(daily_data),
        "ledger_path": str(ledger), "config_sha256": config_hash,
        "candidate": candidate.to_dict(), "baseline": originals,
        "unreviewed_daily_files": additional,
        "public": public,
    }
    return public, private


def validate_prepared_baseline(prepared):
    """Check exact protected source/config bytes before any future installer.

    No caller receives installation authority from this function. It catches a
    new/changed/missing daily file rather than silently replacing user edits.
    """
    if type(prepared) is not dict or prepared.get("purpose") != "review_only_not_activation_authority":
        raise DailyGenerationUnavailable("daily_preparation_invalid")
    root, data = default_daily_paths()
    if (Path(prepared["daily_root"]).resolve() != root.resolve() or
            Path(prepared["daily_data_dir"]).resolve() != data.resolve()):
        raise DailyGenerationUnavailable("daily_location_mismatch")
    root = _existing_root(root)
    _, config_hash = _read_json(data / "config.json")
    if config_hash != prepared["config_sha256"]:
        raise DailyGenerationUnavailable("daily_config_changed")
    candidate = SourceManifest.from_dict(prepared["candidate"])
    if prepared.get("unreviewed_daily_files"):
        raise DailyGenerationUnavailable("daily_unreviewed_source_requires_review")
    baseline = prepared["baseline"]
    if type(baseline) is not list or [r.get("path") for r in baseline] != [e.path for e in candidate.entries]:
        raise DailyGenerationUnavailable("daily_preparation_invalid")
    expected_existing = set(prepared["unreviewed_daily_files"])
    for entry in baseline:
        path = root / entry["path"]
        if entry.get("existed") is False:
            if path.exists():
                raise DailyGenerationUnavailable("daily_baseline_changed")
            continue
        if entry.get("existed") is not True:
            raise DailyGenerationUnavailable("daily_preparation_invalid")
        expected_existing.add(entry["path"])
        data = _read_source(root, entry["path"])
        if (_snapshot_identity(path) != entry["identity"] or
                hashlib.sha256(data).hexdigest() != entry["sha256"]):
            raise DailyGenerationUnavailable("daily_baseline_changed")
    if set(_source_paths(root, require_complete=False)) != expected_existing:
        raise DailyGenerationUnavailable("daily_baseline_closure_changed")
    return None
