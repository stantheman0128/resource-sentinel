#!/usr/bin/env python3
"""Review, or explicitly install and retain the daily accounting owner.

Do not run apply while performing implementation tests. It changes only an
exact reviewed daily source manifest, then performs the separately authorized
daily accounting migration and remains the original supervisor process.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from daily_source_install import (
    PreparedInstall, SourceInstallation, assert_no_sentinel_imports,
    remain_with_source_custody,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-preparation", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--preparation-sha256", required=True)
    parser.add_argument("--backup-directory", type=Path)
    parser.add_argument("--apply-daily-accounting-handoff", action="store_true",
                        help="explicitly apply reviewed source and remain its original resident owner")
    parser.add_argument("--retire-generation-after-drain", action="store_true",
                        help="explicitly request freeze, drain and retirement; daily admission stays fenced")
    parser.add_argument("--restart-after-retirement", action="store_true",
                        help="request one original-owner successor after positive retirement; requires retirement and apply")
    args = parser.parse_args(argv)
    if args.retire_generation_after_drain and not args.apply_daily_accounting_handoff:
        parser.error("--retire-generation-after-drain requires the separately authorized apply action")
    if args.restart_after_retirement and not (args.retire_generation_after_drain and args.apply_daily_accounting_handoff):
        parser.error("--restart-after-retirement requires retirement and the separately authorized apply action")
    if args.apply_daily_accounting_handoff and args.backup_directory is None:
        parser.error("--backup-directory is required for explicit apply")
    operation = None
    try:
        assert_no_sentinel_imports()
        plan = PreparedInstall.load(args.private_preparation,
            candidate_root=Path(__file__).resolve().parents[1], approved_digest=args.manifest_sha256,
            approved_preparation_digest=args.preparation_sha256)
        if not args.apply_daily_accounting_handoff:
            print(json.dumps({"status": "source_review_verified", "manifest_sha256": plan.digest,
                              "files": len(plan.baseline), "runtime_mutations": 0,
                              "activation_authorized": False}, sort_keys=True))
            return 0
        operation = SourceInstallation(plan, args.backup_directory)
        operation.apply()
        operation.enter_daily_host(retire_after_drain=args.retire_generation_after_drain,
                                   restart_after_retirement=args.restart_after_retirement)
        operation.assert_runtime_retired()
        return 0
    except BaseException as error:
        if operation is None and isinstance(error, (SystemExit, GeneratorExit)):
            raise
        reason = getattr(error, "reason", type(error).__name__)
        try:
            print(json.dumps({"status": "blocked", "reason": reason, "activation_complete": False}, sort_keys=True))
        except BaseException as reporting:
            if operation is not None:
                operation.errors.append(reporting)
        if operation is None:
            return 3
        if not operation.source_mutation_attempted and not operation.written and not operation.runtime_started:
            try:
                operation.release_without_source_mutation()
                return 3
            except BaseException as cleanup:
                operation.errors.append(cleanup)
        # Original owner and any uncertain source/native state remain held by
        # this process. No background replacement, PID lookup or force rollback.
        remain_with_source_custody(operation)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
