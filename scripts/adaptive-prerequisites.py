#!/usr/bin/env python3
"""Read-only daily handoff report; optional private preparation, no activation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.adaptive.daily_generation import DailyGenerationUnavailable
from sentinel.adaptive.daily_prerequisites import inspect_daily, validate_prepared_baseline


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    audit = sub.add_parser("inspect")
    audit.add_argument("--candidate-root", default=str(ROOT))
    audit.add_argument("--private-preparation", type=Path,
                       help="new local JSON file; includes private exact paths and hashes")
    check = sub.add_parser("check-baseline")
    check.add_argument("--private-preparation", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "check-baseline":
            with args.private_preparation.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise DailyGenerationUnavailable("daily_preparation_too_large")
            validate_prepared_baseline(json.loads(raw))
            print(json.dumps({"status": "baseline_unchanged", "activation_authorized": False,
                              "mutations": 0}, sort_keys=True))
            return 0
        public, private = inspect_daily(candidate_root=args.candidate_root)
        if args.private_preparation is not None:
            # Exclusive create avoids overwriting evidence/user files. The
            # caller chooses a private local directory; no repo output default.
            with args.private_preparation.open("x", encoding="utf-8") as stream:
                json.dump(private, stream, sort_keys=True, indent=2)
                stream.write("\n")
        print(json.dumps(public, sort_keys=True))
        return 3  # prerequisites blocked, never a native success/skip
    except (DailyGenerationUnavailable, OSError, ValueError, KeyError) as error:
        reason = getattr(error, "reason", "daily_prerequisite_unavailable")
        print(json.dumps({"status": "blocked", "reason": reason,
                          "control_eligible": False, "mutations": 0}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
