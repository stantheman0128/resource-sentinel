# Host integration WIP checkpoint — 2026-09-30

The user requested a commit. This batch is frozen for preservation, not native
promotion or deployment. Its parent is `35bfc1a8395d748774b951f570f062bbbae27dcd`.
Adaptive remains off. P3–P6 are not complete; remaining work includes source
integration as well as native evidence.

## Preserved implementation

- Fixed `python -I` child entry and bounded private registration publication.
- Full role payload included in the original plan declaration and authenticated
  parent release before dispatch to Guardian, Wrapper or shadow Helper hosts.
- Original guardian authority, actor registration and ordered daily/isolated
  launch scopes; Job intent publication before native creation.
- Retained terminal/prelaunch custody after live guardian entries are removed.
- Prelaunch-only aggregate cleanup, immutable host history and original daily
  reservation release.
- Draft authenticated host-closure transport. This has known static mismatches
  and no dedicated tests; its presence does not establish a working closure path.

These changes are confined to 23 source/test files plus this checkpoint and the
planning README. The 14 pre-existing protected tracked files retain their original
hashes. Unrelated untracked files, private evidence and runtime data are excluded.

## Verification

Source commit: `071bc225394a9903780862ff1b8f37c425b78c73`.
Its exact source/test tree is `8d2f82165bdfb1c228096eeffb64e1f362ba1d41`.
It was exported with `git archive`; `PYTHONPATH` was removed before execution.
Windows, base `C:\Python313\python.exe` 3.13.3, ordinary daily Sentinel admission:
HEAVY / P2 / CPU 1 / RAM 1 GiB / IO 0. No exemption was requested.

The bounded run covers the following 17 modules:

```text
tests.test_adaptive_experiment_child_host
tests.test_adaptive_experiment_host_completion
tests.test_adaptive_experiment_job_parent
tests.test_adaptive_experiment_job_publication
tests.test_adaptive_experiment_launch_dispatch
tests.test_adaptive_experiment_role_release
tests.test_adaptive_guardian_experiment_host
tests.test_adaptive_experiment_host_scope
tests.test_adaptive_experiment_host_ledger
tests.test_adaptive_experiment_history
tests.test_adaptive_experiment_release
tests.test_adaptive_experiment_host_transport
tests.test_adaptive_experiment_backing_transport
tests.test_adaptive_experiment_host_authority
tests.test_adaptive_guardian_launch
tests.test_adaptive_guardian_lifecycle
tests.test_adaptive_guardian_host
```

Result: **328 tests; 299 PASS, 2 failures, 27 errors, 0 skips**. The runner took
141.638 seconds (unittest execution: 139.860 seconds), exit code 1. This batch
does not pass its source regression gate. No test expectations or production
behavior were changed after the run to hide these results.

| Module | Observed result requiring follow-up |
| --- | --- |
| `test_adaptive_experiment_child_host` | 1 failure: wrapper partition constructor assertion differs from the actual call. |
| `test_adaptive_experiment_host_ledger` | 1 failure in an existing test: expected `experiment_host_cleanup_unverified`, received `managed_allocation_release_requires_terminal`. |
| `test_adaptive_experiment_host_completion` | 2 errors: `daily_location_mismatch`. |
| `test_adaptive_experiment_job_parent` | 10 errors: `experiment_backing_transport_rpc_failed`. |
| `test_adaptive_experiment_job_publication` | 12 errors: `guardian_existing_registry_required`. |
| `test_adaptive_guardian_experiment_host` | 3 errors: `guardian_host_owner_unavailable`. |

These are observed failure signatures, not a claim that all causes are test-only.
The old baseline was not rerun for this preservation commit; the failure in the
existing ledger test remains an unresolved regression/compatibility concern.
No dedicated retirement-transport tests exist, and no full suite was run.
Raw logs and the exact tree/module manifest stay local under
`.local-adaptive/boundary-20260930-host-freeze/`. The local invocation was:

```powershell
$modules = @(
  'tests.test_adaptive_experiment_child_host',
  'tests.test_adaptive_experiment_host_completion',
  'tests.test_adaptive_experiment_job_parent',
  'tests.test_adaptive_experiment_job_publication',
  'tests.test_adaptive_experiment_launch_dispatch',
  'tests.test_adaptive_experiment_role_release',
  'tests.test_adaptive_guardian_experiment_host',
  'tests.test_adaptive_experiment_host_scope',
  'tests.test_adaptive_experiment_host_ledger',
  'tests.test_adaptive_experiment_history',
  'tests.test_adaptive_experiment_release',
  'tests.test_adaptive_experiment_host_transport',
  'tests.test_adaptive_experiment_backing_transport',
  'tests.test_adaptive_experiment_host_authority',
  'tests.test_adaptive_guardian_launch',
  'tests.test_adaptive_guardian_lifecycle',
  'tests.test_adaptive_guardian_host'
)
$command = 'C:\Python313\python.exe .local-adaptive\verify-boundary-20260930.py host-freeze 8d2f82165bdfb1c228096eeffb64e1f362ba1d41 ' + ($modules -join ' ')
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command $command -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

The export helper and raw logs are local evidence, not tracked runtime artifacts.
To reproduce the same selected suite on a clean checkout of the source commit,
use the same `$modules` list with `$command = 'C:\Python313\python.exe -m unittest -v ' + ($modules -join ' ')`
through the normal wrapper. That is a suite rerun, not a new native gate.

The tests use real isolated SQLite and explicitly synthetic native/readiness/pipe
fixtures. They do not establish Windows capability, recovery, overhead or A/B
gates. No test Job limit was applied in this wrap-up; no production config,
Scheduled Task or global startup entry was changed. `git diff --cached --check`
passes after removing trailing empty lines from three new tests.

## Known incomplete contracts — do not promote

1. Parent fixed dispatcher/listener is not connected. Authentication-file
   publication must be ordered after the original listener is ready, and its
   exact closure must be included in aggregate completion.
2. Aggregate completion handles prelaunch-only cases. It deliberately refuses
   accepted hosts, transport services, Jobs, backings and SupervisorHost. Typed
   terminal receipts and the fifth backing-history table remain unintegrated.
3. `experiment_host_retirement_transport.py` is a draft: `_helper_closed`
   imports `Mode` from a module that does not define it; helper registration
   `_quarantine` and guardian receipt `_changed` versus `_complete` assumptions
   require reconciliation. Snapshot validation/aggregate consumption and dedicated
   protocol tests are absent.
4. Guardian telemetry shutdown can return `stopped: false` without raising.
   The new closed marker must not be accepted as sufficient aggregate closure
   until that result and native custody are checked positively.
5. Job publication replay still applies fresh admission checks after an original
   intent was committed. ACK loss followed by HOLD/freeze can prevent original
   receipt reconciliation. New intent checks must remain strict; an exact
   committed replay requires a separate original-row validation path.
6. Experiment control authority is not integrated into `GuardianControl.apply`.
   Capability assessment must stay outside POLICY. The remaining narrow seam is
   after assessment/original replay and before lifecycle mutation. No control
   dispatch test draft is included in this commit.
7. Guardian actor registration lacks dedicated ordering, ACK-loss and busy-state
   regressions. Full guardian prepare-to-Job and terminal consumer paths are not
   verified by the smaller publication fixtures.
8. Role release for helper still requires the actual SupervisorHost. Full S2/P4
   providers, console topology, S3 drivers, P6 provider/A0 and native gates remain
   source/evidence work; they are not merely commands awaiting user execution.
9. Exact host-ledger guard definitions changed. Older installed schemas fail
   closed; there is no migration or installation in this batch. Canonical source
   inventory also needs to include the new fixed entry before any deployment.

## Next authorized implementation boundary

First repair the recorded source/fixture failures and closure mismatches, then
connect the fixed parent dispatcher and original terminal receipts to complete
aggregate retirement, including backing history. Verify those contracts before
starting any native cohort. Keep capability assessment outside POLICY and keep
original committed replay separate from new admission. Only after this lifecycle
is connected should S2/P4 and S3/P6 providers use it. Existing policy limits and
production-off boundaries remain unchanged.
