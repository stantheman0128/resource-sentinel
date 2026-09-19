# P2 lifecycle evidence lifetime

Date: 2026-09-20. Base: `ca19d841ed0bd4a72a719c7fe65f8194a7baf823`.
This is a lifecycle integration change with adaptive off, not a native capability
pass or an active-control implementation.

## Contract and implementation

`LifecycleStore` previously received bare `LifecycleEvidence` from a callback
and opened its SQLite transaction afterward. That interface did not express how
the provider would retain native handles and launch/mutation fences through the
transaction that consumed its observation.

The constructor now takes an explicit `evidence_provider` returning an evidence
context. Registration, preparation, first launch claim, cancellation, start
failure, root binding, root exit and finalization enter and validate that context
before SQLite. They retain it across the complete transaction and leave only
after commit or error cleanup. Existing transition checks, capacity checks and
CAS predicates remain in place. Read-only terminal/consumed-claim replays remain
read-only and do not require reopening a completed Job.

The provider is trusted runtime code, not serialized caller data. It must obtain
the required policy and Job mutation locks before SQLite, retain the appropriate
handles and fences, and unwind any partial acquisition when entry fails. A
context object alone does not establish native identity, stable observations,
ownership or a launch fence. The default provider still rejects native evidence;
there is no production adapter for a bare assertion. Unit fixtures use an
explicit adapter located only under `tests/fixtures/`.

Evidence cleanup cannot suppress a body/transaction failure or replace its
exception. Secondary cleanup failures attach sanitized notes. SQLite rollback
and connection-close failures now preserve an existing primary exception too.
Cleanup failure after a successful commit reports an error without claiming
rollback; the committed one-use claim remains consumed, and replay returns no
new launch authority. This is an uncertain acknowledgement to reconcile, not
permission to start another command.

## Integration boundary

Four tracked test consumers were migrated to the explicit fixture provider. The
pre-existing, untracked dashboard test has the same minimal local adaptation;
its original content was backed up privately and it remains outside this commit.
No production CLI used the removed fixture-style constructor argument. No
canonical policy entry, runtime configuration, hook, Scheduled Task or adaptive
activation was changed.

## Verification

Environment: Windows build 26340, x64 Python 3.13.3. The clean export of staged
tree `84d60cb93cfaa1806b3b1a0c9372fa211791070d` contains only the committed base
and seven source/test files. It excludes all protected dirty overlay files.
Through normal P2 admission (1 CPU unit, 0.75 GiB RAM, 0 IO slots), with
`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`, **330 tests passed in 19.598 seconds**,
zero failures, errors or skips:

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity tests.test_adaptive_admission_context tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope
```

The 14 new tests use real isolated SQLite transactions to observe entry,
commit/rollback, archive deletion, cleanup order, revision races and consumed
claim replay. They use synthetic authority scopes and prove no native fences.
The full run includes the same three Windows read-only current-process checks
as the previous batch; the other 327 tests are portable. Native launch/control,
recovery, overhead and A/B suites were not run or counted as passing.

The separately preserved local dashboard overlay passed **22 tests in 0.926
seconds**, zero failures/errors/skips, through normal admission (1 CPU unit,
0.5 GiB RAM, 0 IO slots):

```text
py -X utf8 -m unittest tests.test_dashboard_observability
```

Independent review found no remaining actionable correctness defect. All seven
staged source/test blobs match the clean tested export byte for byte. Both exact
normal test reservations were confirmed absent afterward. No exemption, test
Job, CPU restriction or Scheduled Task was created; there is no new cap to
withdraw. Production config SHA256 remains
`75BDD2E0EA382804A95E40C9BCA82D607A9FF96FA44A721DF0908D9049D533F9`.
Private manifests and cleanup evidence remain in `.local-adaptive/`.

## Next seam and gates

This completes the store-side lifetime seam after atomic current-wrapper
admission. A real provider still requires authenticated peer handling, retained
native Job ownership, launch fencing and guardian reconciliation. S1-S3, CPU
effect/recovery, observer overhead and A/B gates remain unverified. These results
must not be represented as completing full native lifecycle or P3-P6.
