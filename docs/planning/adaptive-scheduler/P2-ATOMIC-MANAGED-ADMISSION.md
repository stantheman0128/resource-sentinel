# P2 atomic current-wrapper admission

Date: 2026-09-20. Base: `31871ae8ccb0e663e3dc156ac1c36610098941a0`.
Status: implemented and tested with adaptive off. This is the direct wrapper
admission foundation; it does not complete native lifecycle or pass P1/P3-P6.

## Implemented behavior

`ManagedAdmission.current()` retains the current process's verified native
handle, exact creation FILETIME and logon SID. Arbitrary owner JSON, a PID alone,
or a serialized snapshot cannot enter `Coordinator.admit_managed()`. Native
observations occur before the SQLite write transaction. The fallback session
identifies this exact wrapper; unattributed wrappers share the logon's principal
rather than receiving a new fairness principal for each command.

The context creates immutable execution/task IDs, a private launch claim and
keyed launch-payload hash before the first submission. The managed hash remains
separate from the legacy request hash. The same context verifies the actual
launch payload in memory; a future launcher must call that check before claiming
and launching. Raw command/cwd and the private claim/key are not persisted.
Python objects are a trusted in-process API, not an IPC authentication boundary.

Admission uses the existing shared capacity projection and one SQLite transaction
to create one direct reservation, bind the matching RESERVED lifecycle record,
and remove the queue entry. Binding failure rolls the whole transaction back.
There is no third capacity ledger or adoption of an existing legacy reservation.
Resource-v2, the 58 GiB budget and both 4 GiB reserves are required. Existing
exemption semantics and the three-lease cap are unchanged.

Lost acknowledgement retries return the same allocation and claim identity
without renewal. A removed/expired queue cannot resurrect the same attempt.
Managed queue TTL expires intent even when legacy PID observation is unknown;
reservation TTL still creates a hold and never proves capacity release. Terminal
replay tolerates an intentionally destroyed claim only in the sealed, consumed,
never-started terminal states; it does not recreate launch credentials.

Managed requests carry a durable `managed-v1:` namespace. SQLite INSERT and
UPDATE guards reject conversion into ordinary legacy reservations, including an
older retry that read a queue entry before cancellation and then tries a fresh
insert or fuzzy handoff. The frozen fixture contains the previous commit's real
`admit` and `retry_queued` method bodies. This narrowly verifies those algorithms;
it is not a full older-binary compatibility or production rollout test. Older
accounting/cleanup writers still require the planned handoff before deployment.

Admission results always contain `launch_authorized=False`. No managed CLI,
CreateProcess path, Job enrollment or CPU control is enabled by this change.

## Tests and review

Windows build 26340, Python 3.13.3, 64-bit. All runs used normal live Sentinel
admission and isolated test databases; `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`.
The first focused run had **78 passes and 2 errors out of 80**: queue TTL did not
expire when PID lookup was unknown, and terminal retry rejected the deliberately
cleared claim hash. Both source defects were repaired. The next run passed all
80. Adding old-method compatibility tests gave 86 passes; review then identified
the additional legacy UPDATE handoff path, now guarded and regression-tested.

The final clean export of staged tree
`6ad71aa86227b7474f0b4da853d4c37f85568e59` excluded every protected dirty overlay
file/hunk. **316 tests passed in 13.036 seconds**, zero failures, errors or skips:

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity tests.test_adaptive_admission_context tests.test_adaptive_managed_admission
```

The outer wrapper requested 1 CPU unit, 0.75 GiB RAM and 0 IO slots. These are
313 portable tests and three real Windows read-only current-process identity
checks. One of the latter also binds the real current wrapper in an isolated
database with synthetic capacity inputs. None proves native launch, CPU effects,
restore, observer cost or A/B behavior. Control suites were not run or counted.

Independent source review found no remaining actionable defect in the staged
candidate. The tested export's raw hashes are saved privately; normalized bytes
match all seven staged files (Git archive emitted CRLF while staged blobs use
LF). No semantic source changes occurred after the clean test run.

## Runtime and remaining work

All four exact normal test reservations were confirmed absent afterward. No
exemption, test Job, cap, Scheduled Task or production entry point was created
or changed, so there is no new OS restriction to withdraw. Production config
SHA256 remains
`75BDD2E0EA382804A95E40C9BCA82D607A9FF96FA44A721DF0908D9049D533F9`.
Private manifests and runtime checks remain in `.local-adaptive/`, outside Git.

This implements the direct self-wrapper seam identified in
`P2-NATIVE-FOUNDATION-RESULTS.md`. Hook/waiter adoption, authenticated peer
handling, native launch fencing, guardian preparation and reconciliation remain
unfinished. Routed native control is not introduced. The default native
lifecycle verifier continues to reject unsupported enrollment.

P1 remains blocked by unknown inherited external Job membership and missing
trusted continuous coverage in the daily admission runtime for long control
spikes. This branch's improved accounting has not been deployed. Do not replace
host admission with an isolated ledger, relax grace/reserves, or repeat unchanged
membership-only probes. P3-P6 promotion remains blocked; source foundations may
continue without production activation. No frozen safety invariant is changed.
