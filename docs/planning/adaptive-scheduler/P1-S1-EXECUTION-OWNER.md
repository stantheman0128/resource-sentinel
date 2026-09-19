# P1 S1 execution owner: source integration and remaining native gate

Date: 2026-09-20. Base commit: `f9163b7c15113e728bd2fc9118ad1cb32ae699d1`.
This implements the test-only S1 execution path and its P2 pre-create ledger
support. It does not pass P1 native capability or promote P3-P6.

## Implemented behavior

The S1 runner previously created Jobs and launched fixtures directly. Its
continuous-admission guard prevented execution, but no owner joined the
admission, Job scope, launch claim and recovery lifecycle. S1 now calls
`S1Runtime.open_case()` and keeps an `S1ExecutionOwner` through finalization:

1. Submit one immutable `ManagedAdmission` through the real Coordinator. A
   capacity denial retries the same request with fresh host status/config.
2. Under POLICY and the per-Job mutation fence, register the exact Job name,
   creation nonce and guardian epoch while the allocation is still RESERVED.
   Write the initial recovery record before attempting Job creation.
3. Verify exclusion through the runtime authority, create once, retain the
   original native handle, and transition to PREPARED with scoped evidence.
4. Claim launch once, launch the immutable command, query the exact root identity
   from its retained creation handle, publish that identity and bind the root.
   Lost launch acknowledgement retains START_UNKNOWN and the demand floor.
5. Before CPU control, require the runtime authority's fresh exemption,
   single-victim and host-barrier authorization. Journal intent before Set,
   then Query before publishing applied state.
6. Restore, verify actual empty membership and root exit, seal further launch,
   finalize and only then close owned handles. Failed cleanup retains ownership
   and capacity for recovery.

All S1 cases, including each CPU-effect round, use this path. Reopen tests really
perform restore through the separately reopened handle and cross-check the
original retained handle. These are not all-handles-lost experiments. The
120-second observation window begins after admission, before native preparation.
An observation-query failure cannot suppress the separate restore attempt or
the fixture's voluntary stop.

`LifecycleStore.register_job_scope()` adds persistent `job_nonce`, validates the
exact execution/name/nonce and requires the store's actual held POLICY guard.
Reserved scopes count toward the ten-Job limit before native creation. A native
nonce-bearing proof cannot use the old NULL-nonce prepare path. Cancellation
distinguishes positively never-attempted creation from a created, restored,
verified-empty Job; an uncertain Create call cannot release its allocation.
The guard is thread-scoped and invalidated before native release callbacks.

The separate `TestRecoveryRecord`/`TestRecoveryJournal` stays in `tests/windows`;
it does not relax production `RecoveryManifest` validation. It enforces the
test Job namespace, immutable scope, sequence/hash CAS, intent-before-control,
observed-state publication and exact disabled restoration. Writes fsync content
before atomic publication and retain uncertainty on publication/cleanup errors.
It assumes protected cooperative filesystem ownership, without claiming hostile
same-user path-race protection or directory power-loss durability.

## Verification

Windows 11 build 26340, x64 Python 3.13.3. The normal live Sentinel wrapper
admitted P2 / 1 CPU unit / 1 GiB RAM / 0 IO slots. All lifecycle and recovery
databases/directories used by the tests were isolated. Native spike opt-in was
explicitly zero.

Final clean index export: `a17fe4c03f554ebd79a67756904fcd99a5c80291`.
**481 tests passed, 0 failures, 0 errors, 0 skips, 35.482 seconds.**
The exact module selection, run from that clean export, was:

```powershell
py -m unittest tests.test_adaptive_execution_owner tests.test_adaptive_s1_owner_integration tests.test_adaptive_recovery_journal tests.test_adaptive_job_scope tests.test_adaptive_policy_scope tests.test_adaptive_policy_mutex tests.test_adaptive_finalization_restore tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch tests.test_adaptive_evidence_scope tests.test_adaptive_allocation_transitions tests.test_adaptive_writer_release tests.test_adaptive_legacy_mode tests.test_adaptive_accounting tests.test_adaptive_coordinator tests.test_adaptive_maintainer tests.test_adaptive_managed_admission tests.test_adaptive_writer_fence tests.test_adaptive_legacy_writer_fence tests.test_adaptive_admission_context tests.test_adaptive_continuous_admission tests.test_adaptive_s1_gate
```

The new owner/integration tests use real isolated Coordinator, ManagedAdmission,
LifecycleStore, policy transactions and recovery journal, with explicitly
synthetic Job/process operations and runtime authority. Existing selected tests
also exercise real Windows current-process identity and native POLICY mutexes
with small, owned, naturally ending processes. **No native Job creation or CPU
control test ran.** These results establish source orchestration and ledger
behavior, not the native capability/recovery/overhead/A-B gates.

Review corrections covered restore through the reopened handle, launch-unknown
reconciliation, observation failure during cleanup, admission versus observation
timing, and retrying the same retained mutex after an uncertain release. Failed
release preserves the primary error and exact POLICY recovery nonce. Tests also
cover uncertain Set acknowledgement, journal/DB failures, surviving children,
never-created cancellation and refused finalization/close.

The earlier export `813bcafcc2f9b4d9c487da8f04fa0fd8027ceed0` passed 477 tests
but review identified two remaining claim-failure branches that those tests did
not cover. The final version reconciles an already committed claim even when
CreateProcess was never called, and only drops a retained POLICY guard when its
matching binding has positively cleared the durable nonce. A clean unused-claim
rejection remains cancellable. Four new regressions cover post-claim deadline,
commit-before-release-ACK failure, clean revision conflict, and a changed pending
nonce that must never be replaced or cleared by this owner. Independent review
confirmed all five original findings were fixed before the final passing run.

After the run, the normal test reservation was absent; all nine implementation
and test blobs matched the tested export. The 35 monitored daily source paths
and daily Sentinel configuration hash were unchanged. No production Scheduled
Task, global entry point, exemption or deployment was changed. No test Job
restrictions were created, so there were none to withdraw.

## Actual phase boundary

The formal plan permits small test-only native wrappers in P1. Using a separate
test recovery schema and adding P2 scope registration are supporting changes;
they do not substitute this runner for the production wrapper or guardian.

`tests/windows/adaptive_admission.py` still raises
`continuous_admission_provider_unavailable`. This is an intentionally closed
entry for a **missing implementation**, not a Windows API error. `S1Runtime`
consumes authority operations but does not yet supply the real running-host
authority: continuous accounting across all entry points, fresh exemption
coordination, legacy-writer exclusion, one-victim ownership and barrier release
after verified restoration/accounting. No CLI/environment/receipt unlock was
added. An isolated test ledger cannot prove authority over competing daily
admissions.

The unknown inherited Job observed in earlier host probes is a separate native
topology prerequisite. Neither issue has been resolved by these tests. Full
P1 S1/S2/S3 and native P2 lifecycle remain unverified; P3 production
launcher/guardian/handoff, P4 sampler/helper/shadow policy, P5 canary recovery and
P6 A/B acceptance are still incomplete. Adaptive remains off. Continue with the
actual runtime authority integration, then run the native gates on an authorized
supported test environment. Do not repeat unchanged probes or promote on the
basis of this unit/integration test count.
