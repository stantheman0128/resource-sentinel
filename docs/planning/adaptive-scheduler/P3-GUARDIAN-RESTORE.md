# Retained guardian compare-and-restore

2026-09-20. Production source now consumes restoration requests for Jobs already
adopted by the guardian. This is not cold-start takeover or a native gate pass.

## Connected behavior

`GuardianLifecycle.reconcile()` now consumes `restore_required` instead of only
reporting it. `restore_owned_cap()` and the launch owner's bounded
`restore_owned_caps()` provide explicit withdrawal. Every adopted entry gets an
attempt; one Job's bookkeeping error does not strand a later Job's owned cap.
Unresolved results retain their individual errors and custody.

Under the same POLICY then Job fences, the consumer queries CPU control and
compares it with the exact manifest's original, last-applied and pending old/new
values. Already-disabled control requires no Set. A matching owned cap is
disabled and queried again. An external value is never overwritten. Only after
that native proof may the journal clear its pending intent and the exact control
slot become RESTORED. The admission barrier remains RECOVERY_HOLD; capacity and
legacy exclusion remain until the full lifecycle permits finalization.

Successful adoption retains another native handle to the already-verified
POLICY binding. If DB access fails, restoration can use that same retained mutex
and Job fence without constructing a normal DB PolicyGuard. This path can only
query/disable. It reports native-disabled separately from unresolved journal/DB
bookkeeping and cannot authorize new admission or control.

Unavailable or missing journal storage permits only the previously verified
cached candidates. A readable identity/content/sequence contradiction is sticky
for that entry and cannot become cache authority when a later read fails.
Uncertain file cleanup prevents more journal I/O; uncertain native mutex cleanup
prevents reacquisition. Every call starts with a fresh disabled observation.

Lost publication ACKs require a new successful durable publication before slot
release. Lost finalization/cleanup ACKs revalidate the exact archive, actual
empty Job, disabled control, settled journal and any outstanding slot obligation
before clearing restore-pending custody. The close guard remains strict.

## Validation

The final affected suites passed: tree
`ceb5b930b1fc82c793608a692bcfd1bdedc3a111` ran **64 tests, zero failures,
errors or skips** (runner wall time 15.101 s). The exact exported index was tested
on Windows through the normal daily admission wrapper, with isolated SQLite and
journal files and synthetic native-control fixtures. No real Job CPU limit was
set by these suites; these results are not native recovery acceptance.

The initial isolated candidate
`b1cff4e032a9ed5dffac90ec60f7e0aab0629ea2` ran 307 tests: 304 passed,
one failed and two errored, zero skips (56.009 s). The failure was a NULL-period
fixture incorrectly expecting renewal. Terminal errors exposed the distinction
between reconcilable bookkeeping ACK loss and uncertain native mutex cleanup.

After source fixes and five new fault cases, tree
`5db2115ca94d4e432d5e8665b24e931d46825f1f` ran 312 tests: 311 passed, one error,
zero assertion failures/skips (58.139 s). The remaining old test expected normal
reentry after the native provider's cleanup acknowledgement was lost. The new
contract correctly quarantines this ownership. The final test-only adjustment
asserts no further mutex acquisition or handle close after uncertain native
cleanup, and adds a separate actual SQL nonce-clear commit with lost ACK after
confirmed native release. That case reconciles without a duplicate archive and
then closes custody normally. Production source is identical between the
312-case run and the final 64-case affected rerun. The combined evidence covers
313 distinct passing cases across those runs, not a fresh full 313-case run.

Independent review also required sticky integrity handling across normal and
emergency paths, and explicit provenance on generic native-provider cleanup
errors. A DB nonce-clear failure remains distinct from native cleanup failure.

The broad run used these selectors, after a clean export of the staged tree:

```powershell
py -m unittest tests.test_adaptive_guardian_restore tests.test_adaptive_guardian_lifecycle tests.test_adaptive_guardian_launch tests.test_adaptive_guardian_accounting tests.test_adaptive_production_recovery_journal tests.test_adaptive_control_slot tests.test_adaptive_lease_renewal tests.test_adaptive_launch_store tests.test_adaptive_policy_scope tests.test_adaptive_evidence_scope tests.test_adaptive_exemption_sync tests.test_adaptive_finalization_restore
```

The final affected run used:

```powershell
py -m unittest tests.test_adaptive_guardian_lifecycle tests.test_adaptive_guardian_restore
```

Both were admitted through `scripts/invoke-sentinel.ps1` with HEAVY/P2, one CPU
unit, 1 GiB RAM and zero I/O slots. All three restore-slice reservations were
verified released. The 35 checked daily runtime source files and daily config
are byte-for-byte unchanged from the saved baseline. Tested source matches the
index and task-owned working files. No production configuration, Scheduled Task,
startup entry or adaptive mode was changed. No native test Job limit was created
by this slice, so there is no new native limit to withdraw.

## Scope still outstanding

This consumer handles the current guardian's retained custody. Guardian death,
Job reopen/ownership takeover, independent supervisor, service bootstrap/trusted
endpoint distribution and real loaded-writer/continuous-capacity authority still
need integration. The normal actuator and helper are not enabled by this change.
Native S1-S3, P4 overhead/shadow, P5 fault canary and P6 paired A/B gates remain
unpassed. No portable fixture result substitutes for those measurements.
