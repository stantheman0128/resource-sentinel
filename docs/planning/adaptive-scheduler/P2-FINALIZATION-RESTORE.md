# P2 finalization requires verified restoration

Date: 2026-09-20. Implementation base: `17fb0c1fa20100e90c869121c957053202abe214`.
This is an independent admission-only lifecycle safety repair. It does not
complete P1 native capability or promote P3-P6.

## Problem and resulting behavior

The lifecycle store previously accepted exact empty Job membership, guardian
epoch and a sealed launch as sufficient to finish an execution and archive its
allocation. That boundary did not separately require current CPU restoration or
a settled recovery manifest. Initial disabled state cannot prove later restore;
empty membership cannot establish that pending recovery obligations are settled.
This is a concrete implementation gap against plan sections 4.5, 8.3-8.4 and 9.

`LifecycleEvidence` now has two strict boolean fields, both defaulting to false:

- `current_cpu_disabled`: current native Query verifies disabled CPU control.
- `recovery_manifest_settled`: the matching durable recovery manifest has no
  unresolved intent or active applied cap.

The trusted provider must bind both observations to the exact execution, nonce
and retained Job, holding the policy and Job mutation fences through SQLite
lock waits and terminal CAS/archive commit or rollback. These values are internal
provider evidence, not new public CLI arguments or authenticated authority by
themselves. `original_cpu_disabled` retains its initial-state meaning.

After checking exact Job/epoch, empty membership and launch seal,
`finalize_if_empty` rejects absent or false restoration evidence with
`restore_unverified` before opening its mutation transaction. Direct and routed
capacity, demand floors, nested subspans, runtime revision and archives remain
unchanged. A later verified attempt can finish the same execution. An already
committed FINISHED replay continues to validate caller/revision without requiring
a named Job that may no longer exist, and does not release capacity twice.

No schema, native provider, native control API or runtime setting was added.
The unavailable native provider and continuous-admission preflight remain closed.

## Verification

Windows 11 build 26340, x64 Python 3.13.3. Ran through the normal live Sentinel
wrapper with P2, 1 CPU unit, 0.75 GiB and 0 I/O slots. All test databases were
isolated; `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`. No test Job, CPU control, Scheduled
Task, exemption or workload termination was used.

Clean source tree `34f92a2823b5ae045e5ab2b52e6c94644e0cca9b`:
**328 tests passed, 0 failures, 0 errors, 0 skips, 20.426 seconds.**
The reproducible unittest module selection was:

```powershell
py -m unittest tests.test_adaptive_finalization_restore tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch tests.test_adaptive_evidence_scope tests.test_adaptive_allocation_transitions tests.test_adaptive_writer_release tests.test_adaptive_legacy_mode tests.test_adaptive_accounting tests.test_adaptive_coordinator tests.test_adaptive_maintainer tests.test_adaptive_managed_admission tests.test_adaptive_writer_fence tests.test_adaptive_legacy_writer_fence tests.test_adaptive_admission_context tests.test_adaptive_continuous_admission
```

Five new L1 tests cover direct/routed retention for each missing-proof condition,
unchanged capacity/runtime rows and archives, subsequent successful completion,
old-style initial-only evidence, nested preservation, rejection of public boolean
injection, and a revision race despite otherwise positive proof. Existing tests
exercise exactly-once archival, strict boolean validation, evidence-scope
commit/rollback and release faults. Synthetic fixtures explicitly supply positive
restoration evidence; this is not a Windows restoration result.

The first attempted run could not open the normal admission database inside the
filesystem sandbox and launched no tests; rerunning the same wrapper with its
normal database access succeeded. The first actual test run had 328 tests,
0 failures, 1 error and 0 skips: the new routed assertion named a nonexistent
`routed_reservations` table. Correcting it to the existing `worker_reservations`
table produced the passing result above. No production behavior or assertion
expectation was weakened. Independent review verified the correction and found
no remaining actionable issue.

## Remaining native gate

P2-A remains the delivered boundary. Full native lifecycle and P3-P6 are not
validated. Existing local desktop, isolated current-user Scheduled Task and
Windows CI probes all observed an unknown inherited Job; see
[capability results](CAPABILITY-RESULTS.md),
[desktop results](DESKTOP-HOST-PROBE-RESULTS.md) and
[CI results](CI-HOST-PROBE-RESULTS.md).

The real runtime also lacks the complete continuous-floor/legacy-writer authority
handoff required for S1. An isolated database cannot constrain competing daily
admissions. The next native gate needs a suitable existing Windows test environment
with its own authoritative measurement/admission and verified launch topology.
Current-host runtime alignment would require a separately reviewed activation;
it alone would not resolve the inherited Job. Do not repeat unchanged host probes,
use breakaway, substitute mock evidence, or enable adaptive control to get past
these prerequisites.
