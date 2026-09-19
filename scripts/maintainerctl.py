#!/usr/bin/env python3
"""CLI for the heterogeneous Resource Sentinel maintainer."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.maintainer import Maintainer, Task, Worker, local_host_identity


def read_json(value: str) -> object:
    candidate = Path(value)
    try:
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8-sig"))
    except OSError:
        pass
    return json.loads(value)


def main() -> int:
    default_data = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".resource-sentinel"
    parser = argparse.ArgumentParser(description="Resource Sentinel heterogeneous worker maintainer")
    parser.add_argument("--data-dir", default=str(default_data))
    sub = parser.add_subparsers(dest="command", required=True)

    add = sub.add_parser("worker-upsert")
    add.add_argument("--worker", required=True, help="JSON object or JSON file")
    imp = sub.add_parser("worker-import")
    imp.add_argument("--workers", required=True, help="JSON array or JSON file")
    sync_local = sub.add_parser("sync-local")
    sync_local.add_argument("--status-file", required=True)
    sync_local.add_argument("--config-file", required=True)
    sub.add_parser("workers")
    route = sub.add_parser("route")
    route.add_argument("--task", required=True, help="JSON object or JSON file")
    route.add_argument("--ttl-min", type=int, default=120)
    release = sub.add_parser("release")
    release.add_argument("--reservation-id", default="")
    release.add_argument("--task-id", default="")
    release.add_argument("--outcome", default="success")
    sub.add_parser("snapshot")
    args = parser.parse_args()

    maintainer = Maintainer(args.data_dir)
    if args.command == "worker-upsert":
        result = maintainer.upsert_worker(Worker(**read_json(args.worker)))
    elif args.command == "worker-import":
        result = maintainer.import_workers(read_json(args.workers))
    elif args.command == "sync-local":
        status = read_json(args.status_file)
        config = read_json(args.config_file)
        ram = status.get("ram") or {}
        total_ram = float(ram.get("total_gb") or 0)
        allocatable_ram = float(config.get("local_allocatable_ram_gib") or max(0, total_ram - 16))
        generated = status.get("generated_at") or ""
        try:
            observed_at = datetime.strptime(generated, "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            observed_at = time.time()
        light = str(status.get("light") or "UNKNOWN").upper()
        state = "AVAILABLE" if light in {"GREEN", "YELLOW"} else "CAPACITY_FULL" if light in {"ORANGE", "RED"} else "UNKNOWN"
        v2 = config.get("admission_policy") == "resource-v2"
        if v2:
            state = "AVAILABLE" if (status.get("resource_policy") or {}).get("mode") == "resource-v2" else "UNKNOWN"
        admission_snapshot = {k: status.get(k) for k in ("generated_at", "sampled_at", "cpu_5min_avg", "cpu_pct", "ram", "memory", "disks", "disk_performance", "resource_policy")}
        admission_config = {k: v for k,v in config.items() if k.startswith(('local_', 'disk_', 'heavy_io_', 'admission_'))}
        # Mint the host binding here from this OS; worker aliases cannot create
        # distinct physical pools. This is cooperative scope metadata, not an
        # authorization credential. Existing unbound aliases remain counted.
        canonical_host_id = local_host_identity()
        admission_config["local_host_id"] = canonical_host_id
        system_disk = next((d for d in status.get("disks") or [] if str(d.get("drive")).rstrip(":").upper() == "C"), {})
        computer = os.environ.get("COMPUTERNAME", "local-windows").lower()
        browser_paths = [
            Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Microsoft/Edge/Application/msedge.exe",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
        ]
        browser_ready = any(path.is_file() for path in browser_paths)
        browser_state = (Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data").is_dir()
        docker_cli = shutil.which("docker") is not None
        # A CLI on PATH does not prove the daemon is reachable.  Operators may
        # set local_docker_ready after a separate health probe.
        docker_ready = docker_cli and bool(config.get("local_docker_ready", False))
        result = maintainer.upsert_worker(Worker(
            id=str(config.get("local_worker_id") or "local-windows"),
            provider="local",
            failure_domain=computer,
            capacity_scope="SHARED_POOL",
            capacity_pool=computer,
            max_concurrency=int(config.get("local_max_concurrency") or 8),
            quota_domain=computer,
            state=state,
            automation_level="AUTOMATABLE",
            os="windows",
            capacity_ram_gib=total_ram,
            allocatable_ram_gib=allocatable_ram,
            visible_cpu=float(os.cpu_count() or 1),
            allocatable_cpu=float(config.get("local_allocatable_cpu") or max(1, (os.cpu_count() or 1) - 4)),
            disk_free_gib=float(system_disk.get("free_gb") or 0),
            allocatable_disk_gib=max(0, float(system_disk.get("free_gb") or 0) - 30),
            capabilities={
                "local": True,
                "canonical_host_id": canonical_host_id,
                "host_binding_source": "resource-sentinel-local-sync",
                "enabled": True,
                "adapter": "local",
                "adapter_ready": True,
                "hardware": True,
                "browser": browser_ready,
                "local_browser_state": browser_ready and browser_state,
                "local_network": True,
                "persistent_environment": True,
                "docker": docker_ready,
                "docker_cli_present": docker_cli,
                "observed_free_ram_gib": float(ram.get("free_gb") or 0),
                "memory_headroom_gib": max(0, total_ram - allocatable_ram),
                "light": light,
                "admission_policy": "resource-v2" if v2 else "legacy",
                "admission_snapshot": admission_snapshot if v2 else None,
                "admission_config": admission_config if v2 else None,
            },
            trust_domain="local-private",
            source="resource-sentinel-live",
            observed_at=observed_at,
            probe_expires_at=observed_at + 300,
        ))
    elif args.command == "workers":
        result = maintainer.workers()
    elif args.command == "route":
        raw = read_json(args.task)
        if isinstance(raw.get("allowed_trust_domains"), list):
            raw["allowed_trust_domains"] = tuple(raw["allowed_trust_domains"])
        result = maintainer.route_and_reserve(Task(**raw), ttl_min=args.ttl_min)
    elif args.command == "release":
        result = {"released": maintainer.release(
            reservation_id=args.reservation_id, task_id=args.task_id, outcome=args.outcome
        )}
    else:
        result = maintainer.snapshot()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if not isinstance(result, dict) or result.get("reserved", True) else 2


if __name__ == "__main__":
    raise SystemExit(main())
