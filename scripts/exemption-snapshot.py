"""Read-only lease display probe; the collector owns its external 3s timeout."""
import argparse
import json
import math
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.lease_display import exemption_leases


def installed_limit():
    # Reading the installed implementation's constant is not granting authority.
    # Older code without this constant must not be labelled as enforcing a cap.
    from sentinel import exemptions
    limit = getattr(exemptions, 'MAX_CONCURRENT_EXEMPTIONS', None)
    return limit if type(limit) is int and limit > 0 else None


def read_identities(path, now):
    if path is None:
        return None
    source = Path(path)
    if source.stat().st_size > 8 * 1024 * 1024:
        return None
    with source.open('rb') as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        return None
    snapshot = json.loads(raw)
    sampled = snapshot['sampled_epoch']
    if isinstance(sampled, bool) or not isinstance(sampled, (int, float)) or not 0 <= now - sampled <= 60:
        return None
    nodes = {}
    for row in snapshot['processes']:
        pid, started = row['pid'], row['create_time']
        if (type(pid) is not int or pid <= 0 or pid in nodes or isinstance(started, bool) or
                not isinstance(started, (int, float)) or not math.isfinite(started) or started <= 0):
            return None
        nodes[pid] = started
    return nodes


def snapshot(data_dir, process_snapshot=None, *, now=None):
    now = time.time() if now is None else now
    try:
        limit = installed_limit()
    except (ImportError, AttributeError):
        limit = None
    try:
        nodes = read_identities(process_snapshot, now)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
        nodes = None
    try:
        leases = exemption_leases(data_dir, nodes, now, limit=limit)
    except (OSError, sqlite3.Error, ValueError, KeyError, TypeError, AttributeError, OverflowError):
        leases = dict(state='unknown', occupied=None, limit=limit, next_expiry=None, leases=[])
    return dict(version=1, observed_at=now, exemptions=leases,
                limit_source='installed_exemptions_constant' if limit is not None else 'unavailable')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--process-snapshot-file')
    args = parser.parse_args()
    print(json.dumps(snapshot(args.data_dir, args.process_snapshot_file), ensure_ascii=True,
                     allow_nan=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
