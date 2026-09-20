"""Private collector worker. No adaptive enable, data migration or OS fallback."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.adaptive.contracts import strict_json_loads
from sentinel.adaptive.exemption_sync import ExistingPolicyStore
from sentinel.adaptive.legacy_writer import Candidate, MAX_CANDIDATES, execute_batch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    try:
        with Path(args.input).open("rb") as source:
            raw = source.read(262145)
        if len(raw) > 262144:
            raise ValueError("input_too_large")
        value = strict_json_loads(raw)
        if (type(value) is not dict or set(value) != {"protocol_version", "candidates"} or
                type(value["protocol_version"]) is not int or value["protocol_version"] != 1 or
                type(value["candidates"]) is not list or len(value["candidates"]) > MAX_CANDIDATES):
            raise ValueError("input_invalid")
        directory = Path(args.data_dir).resolve()
        store = ExistingPolicyStore(directory / "sentinel.db")
        logon = store._policy.current_logon()
        candidates = [Candidate.from_dict(item, logon) for item in value["candidates"]]
        result = execute_batch(store, directory / "exemptions.sqlite3", candidates)
    except Exception:
        # A crash/timeout may follow a Set: no synthetic successful ACK, no retry.
        result = {"protocol_version": 1, "available": False,
                  "reason": "legacy_batch_unavailable", "results": []}
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result["available"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
