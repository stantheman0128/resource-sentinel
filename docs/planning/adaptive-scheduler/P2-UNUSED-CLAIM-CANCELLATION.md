# P2 native current-wrapper cancellation before handoff

Date: 2026-09-20. Base: `4fd9262a6962489f337f000adca7b7018ae0e3d6`.
Adaptive remains off. This is a narrow native identity integration, not a Job
launch, CPU-control or S1-S3 capability result.

## Authority and transaction boundary

`ManagedAdmission.cancel_reserved(db_path, reservation_id=..., expected_revision=...)`
can cancel its own atomic direct admission while its retained native current
process identity remains verified, the lifecycle is `RESERVED`, and its private
one-use launch credential has never been exported. The caller supplies the exact
reservation ID returned by admission. Context, lifecycle and allocation bindings
must agree, including resources, request key, owner identity and spec hashes.
Submission binds the context to its canonical Coordinator ledger path before
the admission transaction; cancellation against another path, including a
matching SQLite backup, fails before sealing the context.

`launch_claim_token()` permanently records credential export before returning it.
After export, an empty Job or a database row still saying `RESERVED` cannot
authorize this cancellation. PREPARED, claimed, launched, uncertain, foreign,
closed-context and mismatched allocations remain outside this path.

Before providing the store's scoped evidence, cancellation irreversibly seals
submission, payload verification and credential export and destroys the private
token/key. The context lock retains exclusive custody through SQLite completion;
it is not a kernel mutex or a general cross-process launch fence. Native identity
queries happen before the writer transaction. Python objects are trusted runtime
implementation, not a security boundary against hostile code in the same process.

A bounded canonical digest binds the lifecycle row (including the private claim
hash) and direct allocation. The store revalidates the authoritative allocation
and recomputes that digest under the writer lock before archiving/releasing it.
This closes the gap between native preflight and commit even if an inconsistent
writer changes ownership, request data or claim flags without advancing the
lifecycle revision. Only heartbeat and allocation deadline refreshes are omitted
from that digest; neither establishes termination or invalidates unused custody.

Failure or lost acknowledgement never unseals the context. An exact retry can
reconcile cancellation with the same target. Terminal replay verifies destroyed
claim, absent active allocation and one cancellation archive. Closing the handle,
expiring a reservation or starting a new wrapper cannot reconstruct this proof.
Each valid proof records the latest attempted revision, allowing an exact retry
after a failed cancellation, legitimate floor revision and lost terminal ACK.

## Boundary relative to the formal plan

This implements a safely separable part of the P2 lifecycle contract after
atomic admission and scoped evidence integration. The generic lifecycle provider
still rejects unavailable native evidence. There is no public CLI accepting a
serialized proof, adoption of another owner's reservation, PREPARED cancellation,
Job creation, guardian, launcher, or production wrapper activation in this change.

The remaining native launch, recovery, writer handoff, overhead and A/B gates
retain their previous status. Full native lifecycle and P3-P6 are not complete.

## Verification

Environment: Windows build 26340, x64 Python 3.13.3. Clean staged tree
`292a689cc3cec8773216198ca7c0e8b35a5f0b01`, exported using raw Git blob bytes,
passed **375 tests in 28.766 seconds**, zero failures, errors or skips. The
normal live P2 wrapper admitted 1 CPU unit, 0.75 GiB RAM and 0 IO slots;
`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` kept Job/control spikes disabled.

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity tests.test_adaptive_admission_context tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope tests.test_adaptive_legacy_mode tests.test_adaptive_native_cancel
```

Of these, 371 tests use portable fixtures. Four exercise Windows current-process
identity, including one new real retained-self cancellation against isolated
SQLite with synthetic capacity. That smoke verifies the original reservation is
archived exactly once and adaptive remains off; it performs no workload launch,
Job assignment or control write. The 17 other new cancellation tests cover
exported/closed/unknown identity, exact bindings, copied-ledger rejection, field
mutation between proof and transaction, serialized export/close, permanent seal
after rollback, actual floor revision before lost-ACK replay, malformed evidence
and allowable heartbeat/deadline refresh. One new admission-context test covers
canonical ledger binding and cross-ledger retry rejection.

The first targeted run had 76 passes and two cleanup errors caused by test-only
SQLite connections left open on Windows. Explicit connection closing corrected
both; the exact two leftover test directories were subsequently verified and
removed. After the review fixes, the focused suite passed 83 tests in 3.138s.
Independent review identified and corrected copied-ledger cancellation and
revision-changing lost-ACK replay, then found no remaining actionable issue in
this bounded path. The final clean 375-test run includes all those corrections.

All tested source/test blobs match the staged candidate; protected dirty overlay
files are excluded. No test Job, cap, exemption or Scheduled Task was created,
and no daily runtime/config/policy entry was changed. Normal test reservations
are checked separately for release. Production config SHA256 remains
`75BDD2E0EA382804A95E40C9BCA82D607A9FF96FA44A721DF0908D9049D533F9`.
Private manifests and cleanup records stay in `.local-adaptive/`.
