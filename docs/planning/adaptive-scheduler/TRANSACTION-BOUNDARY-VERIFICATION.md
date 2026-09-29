# Transaction boundary source verification — 2026-09-30

This batch implements the user-approved
[transaction observation correction](DAILY-READINESS-TRANSACTION-DECISION.md).
It is source regression evidence, not permission to deploy or evidence that
P3–P6 native gates passed.

## Exact source and scope

- Baseline commit: `3d3e934ee7959e89d03e8f8231f8c909c91de4e0`.
- Source commit: `bee5c5ccf353ab1c988286fec407e01c61a41a4a`.
- Broad regression tree: `a3383e37fe27cf6a9a94f7d73e7e8b345d4bcdad`.
- Final source tree: `b7f10451c2b4ec68f82e6824cb36c66d10e90681`.
  The sole difference is `tests/test_adaptive_daily_retirement_policy.py`;
  all production source and all other tests are identical.
- Windows, `C:\Python313\python.exe` (Python 3.13.3); exported with
  `git archive`, with PYTHONPATH cleared.
- Normal daily admission: HEAVY/P2/CPU1/RAM1GiB/IO0. No exemption.
- Actual isolated SQLite transactions, rollback/replay and source-audit probes;
  native/readiness collaborators in the new boundary tests are explicit fixtures.
  These tests do not establish native launch/control/recovery or monitoring cost.
- Fourteen protected tracked files retain their original hashes and are excluded.
  Runtime configuration, production Scheduled Tasks and global entry points are
  not part of this change. No test Job restriction was applied by this batch.

## Behavior and intentional contract change

Actual process/file/source checks happen before BEGIN. SQL checks the same
connection, complete generation, original owner/handle, closed/poison state and
unextended deadline without process/filesystem probes. Final Create and both Set
paths revalidate the original authority after SQL and carry the original deadline
to the native call. No-Set renewal also validates before renewing control state.

The approved semantic difference is explicit: a peer dying or file changing
after BEGIN can leave a conservative SQL intent, but must not authorize native
work. The old per-write observation assertions now test that intent retention
and final rejection. Nonce-only cleanup requires positive original native exit
or no-entry evidence. Lost publication responses and constructor failure retain
the original wrapper binding; they cannot release daily capacity or create a
replacement owner.

Existing synthetic host-authority tests now use a deterministic monotonic clock,
plus an explicit 251 ms expiry rejection. The real 250 ms budget was not changed.
The formerly missing experiment launcher fixture exercises real isolated
two-ledger bookkeeping with explicitly synthetic native and wire collaborators.

## Results

The 51-module run on the broad regression tree ran **1,150 tests: 1,140 passed,
0 failures, 10 errors, 0 skips**, runner 402.488 seconds. Every error was in
`DailyRetirementPolicyScopeTests`: its SQL-only fixture called nonce cleanup
without positive original native release/no-entry evidence and was rejected
before opening SQL (`daily_readiness_cleanup_not_owned`).

Only that fixture was then updated: explicit synthetic positive no-entry evidence
in setup (including the nested guard), preserving all ten original assertions.
One added test verifies missing, contradictory and non-boolean native facts
refuse before SQL and preserve nonce/cleanup state. No production check was
changed. On the final tree, the repaired module plus
`test_adaptive_daily_readiness_transaction_boundary` and
`test_adaptive_policy_cleanup_custody` ran **32 PASS, 0 failures/errors/skips**,
runner 2.997 seconds. The full 51-module set was not rerun after this test-only
change; these overlapping results are not added into a single pass total.

The source commit contains the final exported tree; tests did not depend on
uncommitted source from the working tree. Documentation is committed separately.

Private logs remain under `.local-adaptive/boundary-20260930-*/`; no runtime
configuration, databases, environment dumps or private diffs are published.
Earlier attempts are retained there, not counted as passes or added together:

| Attempt | Tests | Failures | Errors | Skips | Outcome |
| --- | ---: | ---: | ---: | ---: | --- |
| Baseline | 373 | 0 | 2 | 0 | Missing WIP fixture; real-clock expiry in synthetic fixture |
| Candidate 1 | 548 | 2 | 9 | 0 | Fixture preparation and copied-scope error contract repaired |
| Candidate 2 | 133 | 2 | 1 | 0 | Found actual filesystem check inside lifecycle transaction |
| Candidate 3 | 42 | 1 | 0 | 0 | Found cold-import source audit inside release transaction |
| Candidate 4 | 42 | 0 | 0 | 0 | Focused cleanup/lifecycle regression passed |
| Broad regression | 1,150 | 0 | 10 | 0 | Same SQL-only no-entry fixture omission in ten cases |
| Final targeted rerun | 32 | 0 | 0 | 0 | Fixture correction and negative proof coverage passed |

The cold-import regression was rerun first in a fresh interpreter. Dependencies
are loaded before preflight provenance attestation; the audit and transaction
spy were preserved. The wider run below intentionally covers actual consumers
of the shared transaction change, not the entire repository.

## Reproduce affected source regression

Run from the implementation checkout or an export of the exact source tree,
using normal host admission. This does not install a daily generation or enable
adaptive control.

```powershell
$sentinelBoundaryTests = @(
    'tests.test_adaptive_daily_readiness_pins'
    'tests.test_adaptive_daily_readiness_transport'
    'tests.test_adaptive_daily_readiness_lock_boundary'
    'tests.test_adaptive_daily_readiness_transaction_boundary'
    'tests.test_adaptive_daily_generation'
    'tests.test_adaptive_policy_cleanup_custody'
    'tests.test_adaptive_daily_monitor'
    'tests.test_adaptive_experiment_remote_readiness'
    'tests.test_adaptive_daily_activation_host'
    'tests.test_adaptive_cleanup_transaction_boundary'
    'tests.test_adaptive_experiment_host_authority'
    'tests.test_adaptive_experiment_host_roles'
    'tests.test_adaptive_wrapper_host'
    'tests.test_adaptive_launcher'
    'tests.test_adaptive_guardian_control'
    'tests.test_adaptive_guardian_control_frames'
    'tests.test_adaptive_daily_successor'
    'tests.test_adaptive_daily_successor_console'
    'tests.test_adaptive_daily_successor_cycle'
    'tests.test_adaptive_daily_successor_epoch'
    'tests.test_adaptive_daily_successor_history'
    'tests.test_adaptive_daily_successor_host'
    'tests.test_adaptive_daily_successor_host_registration'
    'tests.test_adaptive_daily_successor_inventory'
    'tests.test_adaptive_daily_successor_predecessor'
    'tests.test_adaptive_daily_successor_registration_inventory'
    'tests.test_adaptive_daily_successor_startup'
    'tests.test_adaptive_daily_successor_startup_inventory'
    'tests.test_adaptive_daily_retirement'
    'tests.test_adaptive_daily_retirement_consumers'
    'tests.test_adaptive_daily_retirement_fence'
    'tests.test_adaptive_daily_retirement_integration'
    'tests.test_adaptive_daily_retirement_inventory'
    'tests.test_adaptive_daily_retirement_policy'
    'tests.test_adaptive_daily_retirement_prelaunch'
    'tests.test_adaptive_daily_retirement_successor_history'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_release_custody'
    'tests.test_adaptive_experiment_release_hooks'
    'tests.test_adaptive_experiment_release_native'
    'tests.test_adaptive_experiment_demand'
    'tests.test_adaptive_experiment_admission_settlement'
    'tests.test_adaptive_experiment_unadmitted_cleanup'
    'tests.test_adaptive_experiment_scope'
    'tests.test_adaptive_lifecycle'
    'tests.test_adaptive_coordinator'
    'tests.test_adaptive_maintainer'
    'tests.test_adaptive_policy_fencing'
    'tests.test_adaptive_policy_scope'
    'tests.test_coordinator'
    'tests.test_maintainer'
)
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command ('C:\Python313\python.exe -m unittest -v ' + ($sentinelBoundaryTests -join ' ')) -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

## Remaining scope

The README remains the current source/gate inventory. Fixed child bootstrap and
Release dispatch, guardian experiment authority integration, aggregate completion,
S2/P4 providers, remaining S3 drivers/orchestration, and the actual P6 A/B/A0
provider still need source work. New S1 serial source does not call the old
continuous-admission placeholder, but canonical daily source readiness and real
S1 execution are unverified. Old S3/P6 paths still depend on that placeholder.
No required native, recovery, overhead or A/B gate is declared passed here.
