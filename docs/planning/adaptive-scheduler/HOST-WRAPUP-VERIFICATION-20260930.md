# Host integration wrap-up verification — 2026-09-30

This is a source checkpoint requested by the user. It does not enable production
adaptive control or establish P3–P6 native acceptance.

The user subsequently explicitly requested pause and wrap-up. The goal is
paused; source work and tests have stopped. Commit/push and this handoff are
the only remaining wrap-up actions. Resume implementation only on user request.

## Independently verified mutex fix

Source commit: `fb1f8fe6a1be4ed06ec70b7a2d7be584292464e3`.
Exact exported tree: `fa7f25ca54f395bbd3fdf43e3a841753f7e3a233`.

The supervisor retains the same Windows singleton name, ACL, wait and cleanup
behavior. A typed lifetime owner separates that lease from POLICY/Job critical
sections; real POLICY/Job ownership still blocks RPC. Cross-registry recursive
acquisition remains rejected.

**74 tests passed, 0 failures, 0 errors, 0 skips; 13.638 seconds.**
Five test selections: `test_adaptive_supervisor_instance_mutex`,
`test_adaptive_policy_mutex.PolicyMutexTests`,
`test_adaptive_policy_mutex.RetainedNativeCustodyTests`,
`test_adaptive_supervisor_startup`, and
`test_adaptive_daily_successor_startup`. Native effects use explicit fixtures.
These results do not establish Windows singleton/recovery gates.

## Host integration candidate

Exact exported tree: `2df276b1a58dba31137f3da930c9d49ab55fe9e7`.
The 21 source/test files connect:

- The original parent dispatcher to fixed authenticated child, backing, Job and
  retirement protocols; bounded polling retains uncertain native cleanup.
- Actual SupervisorHost startup, guardian recovery and deliberate drain to
  predeclared experimental children and their original creation handles.
- Guardian parent identity, original launch owner and telemetry closure custody.
- Typed terminal receipts and v4 aggregate completion to actual isolated
  lifecycle/history/backing records before daily capacity release.
- Retry after a clean readiness refusal only when the original readiness group
  positively closes before POLICY entry.
- Original SQLite connection identity captured at submission/abandonment
  creation, before BEGIN. A foreign closed connection or copied transaction
  cannot substitute for that original owner.

The source retains the approved transaction boundary: OS/file observations
before SQL, metadata checks inside SQL, and fresh checks before native writes.
No change to the exemption cap, admission reserves or control eligibility.

Source checkpoint: `ea20e4aacf694e24ce957c42bff98eb5429b32dd`.
Its tree exactly matches the tested candidate above. There are no unstaged
source dependencies.

**32 modules, 702 tests; 688 passed, 0 assertion failures, 23 error records,
0 skips; 288.574 seconds.** The 23 error records affect **14 distinct cases**:
five admission-retirement cases and nine managed-completion cases. Each of the
nine latter cases also reports a cleanup error. Thus this is not 23 distinct
failed tests, and it is not a passing integration gate.

The two recorded error families are:

1. `experiment_host_retirement_admission_transaction_unsettled` in five
   `OriginalAdmissionRetirementTests` cases. The trace reaches
   `_closed_transaction` in the connection-closed/type check. Next inspect the
   actual Coordinator connection owner and its close evidence without weakening
   the original-connection identity requirement.
2. `experiment_child_original_native_custody_changed` in all nine
   `ManagedAggregateCompletionTests` cases, including their cleanup. The trace
   reaches `ExperimentChildBinding.close()` through the original client pin.
   Next reconcile the fixture/actual handle transition with the retained
   original owner; do not replace an owner or infer closure from a snapshot.

No further source changes were made after this frozen verification. The user
requested a commit checkpoint, so both the unfinished source and its failing
evidence are preserved explicitly as WIP. The earlier 74-test mutex run and
this 702-test run have overlapping selections and must not be added together.

## Reproduction and local evidence

Both runs use Windows and base Python 3.13.3, normal daily
HEAVY/P2/CPU1/RAM1GiB/IO0 admission, and a `git archive` export of the exact staged
tree with PYTHONPATH removed. No unstaged source is imported.

Private evidence is retained locally:

- `.local-adaptive/boundary-20260930-singleton1/{manifest.json,test.log}`
- `.local-adaptive/boundary-20260930-host-wrapup1/{manifest.json,test.log}`

Raw evidence and runtime data are not added to the repository. To reproduce the
host selection from a checkout containing the checkpoint, use the installed
base interpreter through normal daily admission:

```powershell
$sentinelHostWrapupTests = @(
    'tests.test_adaptive_experiment_host_retirement_transport'
    'tests.test_adaptive_experiment_host_completion'
    'tests.test_adaptive_experiment_managed_completion'
    'tests.test_adaptive_experiment_host_dispatch'
    'tests.test_adaptive_experiment_supervisor'
    'tests.test_adaptive_experiment_scope_retry'
    'tests.test_adaptive_guardian_experiment_host'
    'tests.test_adaptive_guardian_host'
    'tests.test_adaptive_experiment_host_scope'
    'tests.test_adaptive_experiment_host_transport'
    'tests.test_adaptive_experiment_role_release'
    'tests.test_adaptive_experiment_host_ledger'
    'tests.test_adaptive_experiment_host_backing'
    'tests.test_adaptive_experiment_history'
    'tests.test_adaptive_experiment_history_consumers'
    'tests.test_adaptive_experiment_release'
    'tests.test_adaptive_experiment_release_custody'
    'tests.test_adaptive_experiment_partition_admission'
    'tests.test_adaptive_experiment_child_host'
    'tests.test_adaptive_experiment_job_parent'
    'tests.test_adaptive_experiment_job_publication'
    'tests.test_adaptive_experiment_control_dispatch'
    'tests.test_adaptive_supervisor_host'
    'tests.test_adaptive_supervisor_startup'
    'tests.test_adaptive_abandon_admission'
    'tests.test_adaptive_managed_admission'
    'tests.test_adaptive_admission_context'
    'tests.test_adaptive_coordinator'
    'tests.test_coordinator'
    'tests.test_adaptive_experiment_admission_settlement'
    'tests.test_adaptive_experiment_host_authority'
    'tests.test_adaptive_experiment_host_consumers'
)
powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command ('C:\Python313\python.exe -m unittest -v ' + ($sentinelHostWrapupTests -join ' ')) -ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0
```

## Remaining gates and protected state

- Full S2/P4 provider and console topology are not complete.
- The P4 query-only cohort still lacks an original query owner and positive
  closure capability. Completion explicitly refuses it.
- S3 orchestration and the P6 provider/A0 remain source work.
- Readiness acquisition failure before the group yields still retains custody
  when original cleanup cannot be proved. The clean post-yield retry fix does
  not solve this separate case.
- Native capability, recovery, overhead and comparable P6 A/B remain unverified.
  There is no basis to promote production adaptive control.
- The 14 protected pre-existing files and unrelated untracked work stay outside
  these commits. No daily config, official Scheduled Task or global entry was
  changed. This verification applied no native Job CPU limits and performed no
  user-process kill/trim/suspend tests.

Next implementation work starts from the recorded test failures, then completes
the remaining providers. The gaps are not described as only user-console work.
