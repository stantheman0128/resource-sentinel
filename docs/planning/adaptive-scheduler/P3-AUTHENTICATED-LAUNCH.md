# Authenticated wrapper-to-guardian launch

2026-09-20. Continues from `a15e251` without deploying the candidate or changing
daily runtime configuration. This is a P3 integration slice, not a P3-P6 gate pass.

## Connected source path

`ManagedLauncher` retains a real `ManagedAdmission` across direct admission and
queued retries. The original command is bound privately in that context; the
wrapper constructs its deterministic trusted system `cmd.exe` command line only
for native creation. The guardian never receives raw command, cwd or environment.

The launch transport has three fixed authenticated operations: PrepareExecution,
ClaimLaunch and BindRoot. Native server pinning precedes the claim credential;
fresh challenges, complete transcript MACs, bounded frames and one connection
deadline cover each exchange. Callers retain a stable request ID for each phase.
Receipt drains the transport and is not a durable mutation acknowledgement.

The shared store records three bounded operation slots per execution, containing
only IDs, spec/epoch and complete request digests. Same-key changed payloads are
rejected. Auth is revalidated with actual allocation and lifecycle data inside
the deciding transaction. Claim replay never grants another native launch.
This is an additive, undeployed internal table, not an alternate capacity ledger.

`GuardianLaunchOwner` registers the exact planned scope and durable formal
manifest before native Job creation. It shares one evidence dispatcher and the
same POLICY/per-Job fences with `GuardianLifecycle`. Authenticated wrapper/root
handles are duplicated into guardian-owned limited-right handles; a pipe's
borrowed peer handle is never passed directly into long-lived custody. A root
locator is interpreted only inside the verified peer's handle table and must
match the complete expected identity and positive native Job membership.

After one claim, the wrapper seals its Create capability before native entry.
An uncertain Create/ACK never invokes the command again. Bind uses the retained
root, publishes its exact identity, seals the ledger, and transfers existing
Job/wrapper/root owners and their mutex into the lifecycle consumer. Root exit
does not release the Job or its allocation. The guardian retains surviving
children; verified terminal accounting remains the prior consumer's contract.

Initial journal publication ACK loss requires durable reaffirmation of the same
initial record while a retained never-created fence is still true. Bind journal
ACK loss accepts only the exact expected successor, then requires another
successful durable publication. A lost DB/adoption ACK revalidates existing
state and owners; it does not recreate an object or duplicate a command.
Cleanup uncertainty preserves native/file owners and stops affected retries.

## Current limits

The new path permits explicit background P2/P3 direct wrapper invocations only.
It writes no CPU controls. Default launcher readiness and guardian host authority
refuse enrollment. Real continuous host accounting and loaded-writer exclusion
must come from a compatible, running candidate cohort; serialized flags and
fixture callbacks are not substitutes. Existing query IPC remains compatible.

Service bootstrap/trusted endpoint distribution, an independent supervisor,
restore-only takeover, complete lifecycle lease renewal and the production
normal actuator still require integration. Existing PS/global entry points are
unchanged. Foreign-parent Job and full native launch/recovery gates remain
unverified; the earlier limited empty-Job smoke does not resolve them.
P4 overhead/shadow and P5/P6 canary/A-B acceptance remain outstanding.

## Validation

Executed on Windows on 2026-09-20 through the daily Sentinel wrapper with
`-ResourceClass HEAVY -Priority P2 -CpuUnits 1 -RamGiB 1 -IoSlots 0` and no
exemption. Each run used a clean export of the exact staged Git tree, excluding
the protected incoming working-tree overlay. Fixtures used isolated databases.

The first candidate, tree `5bdc79745faccb594acc218f27708d741d3c274b`, ran 515
tests: 494 passed, 21 errors, zero assertion failures and zero skips (47.695 s).
All 21 errors came from the new guardian fixture requesting less than the
existing 0.05 GiB RAM minimum; none reached the launch implementation. The fixture
was corrected to request 128 MiB physical / 256 MiB Commit; policy was unchanged.

The corrected tree, `822da7070b1e7da98ed300ae5773dadb23c2088a`, differs only in the
guardian tests and native-transfer test cleanup. Its affected rerun passed all
46 tests, zero failures/errors/skips (13.519 s). This includes one added terminal
custody case and the explicitly selected native cross-process transfer smoke.
Across these runs, 517 distinct tests have passing evidence; this is not a claim
that a fresh 517-test suite was run against the second tree.

The executed test selections, expressed as the equivalent unittest command in
each clean export, were:

```powershell
py -m unittest tests.test_adaptive_guardian_launch tests.test_adaptive_identity_transfer tests.test_adaptive_launch_store tests.test_adaptive_launch_transport tests.test_adaptive_launcher tests.test_adaptive_native_launcher.NativeLauncherTests tests.test_adaptive_production_recovery_journal tests.test_adaptive_identity tests.test_adaptive_identity_cleanup tests.test_adaptive_identity_exit tests.test_adaptive_guardian_lifecycle tests.test_adaptive_guardian_accounting tests.test_adaptive_ipc tests.test_adaptive_native_ipc tests.test_adaptive_lifecycle tests.test_adaptive_evidence_scope tests.test_adaptive_job_scope tests.test_adaptive_prelaunch tests.test_adaptive_registration_publication tests.test_adaptive_finalization_restore tests.test_adaptive_managed_admission tests.test_adaptive_policy_scope tests.test_adaptive_s1_owner_integration
py -m unittest tests.test_adaptive_guardian_launch tests.test_adaptive_identity_transfer tests.test_adaptive_identity_transfer.NativeTransferSmoke.native_cross_process_duplicate
```

The native smoke copied a retained process handle from one voluntarily exiting
test child, checked the full identity, and observed its real exit through both
copies. The child exited normally, all parent handles closed, and cleanup
reported no errors. It created no Job and wrote no CPU control; it proves this
cross-process ABI primitive, not managed launch containment or crash recovery.
Existing Windows Named Pipe tests also passed in the first run. Portable launch
and guardian fixtures are not substitutes for native capability acceptance.

Post-run verification found both daily test reservations released, all 35
checked daily source files unchanged, daily config unchanged, and all candidate
source/test bytes matching the tested export. No test Job cap was introduced,
and no daily Scheduled Task, global entry point, runtime schema or configuration
was deployed. P3 remains incomplete; P4-P6 have not passed their gates.
