# P3 legacy writer handoff implementation evidence

This slice implements the actual collector write boundary and closes first-scope
publication races. It does **not** establish a complete P3 exit, Windows CPU
capability, or permission to enable adaptive control. Production default remains
off; the daily checkout, runtime configuration and Scheduled Tasks are untouched.

## Implemented consumers

- `Coordinator.admit_managed()` publishes its first RESERVED wrapper while
  owning the real shared POLICY. `commit_managed_admission()` independently
  requires that held scope and revalidates its nonce inside the capacity
  transaction. A failed lock attempt does not consume the first-submission
  marker. Confirmed rollback differs from uncertain commit/cleanup.
- `LifecycleStore.prepare_registration()` and `mark_prepared()` join the same
  publication fence, including routed/nested registration and the older prepare
  path. Borrowed ownership is not released or reacquired by the callee.
- The collector submits exact PID/FILETIME candidate operations to one Python
  worker. The worker holds POLICY through registry/grant reads, native Job
  membership checks, actual priority/I/O/trim writes and native handle cleanup.
  A permission response followed by a PowerShell setter is not used.
- The native process backend opens one mutation handle with the operation's
  required rights, duplicates that same handle for exact identity verification,
  and retains it through Set. Job handles request query/read-control rights,
  validate canonical registered names and the explicit logon-SID descriptor.
- RESERVED wrappers and every active/uncertain registered Job remain excluded
  regardless of feature mode, cap state or root exit. Registered guardian,
  helper and supervisor identities use the same POLICY and registry revision.
  Removal requires positive death on the retained process identity.
- Collector exemption restore, resource-v2/legacy demotion, GREEN restore and
  RAM trim all use this boundary. Wrapper's separate priority setter is removed.
  Missing/unknown registry, grants, identity or membership cannot authorize a
  write. Collector reporting continues and reports enforcement availability.
- Each batch has a 250 ms work deadline. Sequential ledger reads share that
  deadline rather than each starting a new 250 ms SQLite wait. No following Set
  begins after the deadline; a native call already in progress, its readback and
  cleanup are not hard real-time guarantees.

## Intentional limits and incomplete integration

1. Infrastructure initialization is explicit and requires POLICY; the collector
   does not create or migrate a missing authority database. The production
   supervisor that invokes registration still needs implementation. Missing
   initialization therefore stops this source version's legacy writes.
2. Existing exemption records use float birth timestamps and do not prove native
   ancestry. While such a lease is active, the worker conservatively suppresses
   constraining actions for all candidates. It may restore an independently
   verified unmanaged target; a purported restore to Idle is still constraining.
   Exact native grant/ancestry integration remains required before promotion.
3. The incoming, untracked `change-tracker.ps1` and `change-tracker.py` overlay
   contains two additional priority setters. It was not silently imported into
   this commit. Full loaded-writer handoff remains incomplete until those local
   sources are reconciled and every actual writer uses the boundary.
4. Legacy PID-only demotion maps are not new Job restore evidence. Managed
   scopes cannot reach that restore path. Class 33 I/O priority remains the
   existing undocumented Windows compatibility operation; it is not evidence
   of a supported adaptive actuator. Its NTSTATUS is now checked.
5. The native backend's own process/Job handles retain failed cleanup for retry.
   Existing identity/security helpers also check cleanup, but not every internal
   token/security-buffer allocation has a retry API. Unknown cleanup does not
   produce a successful batch acknowledgement.

## Validation

Windows, x64 Python 3.13, normal live Sentinel admission at P2 / CPU 1 / RAM
1 GiB / I/O 0. `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` throughout. Each candidate
was exported from its exact Git index tree; pre-existing working-only changes
were excluded from that reproducible export.

| Candidate | Result |
|---|---|
| `4f9fa3dbb482ae35d5172dc6344fee32aa82c00e` | 514 Python tests: 14 failures, 3 errors, 0 skips; both PowerShell tests passed |
| `12bd7c8712153a156f52359d8409105528b97f42` | 517 Python tests: all passed, 0 failures/errors/skips; both PowerShell tests passed; 95.312 seconds including PowerShell |
| `f3f1e46c382e9766d96dccb36118f3ce921ef88a` | Only one additional regression test differs from the preceding candidate; all 23 tests in its module passed, 0 failures/errors/skips, 3.491 seconds |

The first run found a real publication cleanup defect: a positively rejected
pre-transaction evidence binding left POLICY busy after successful cleanup.
Only the exact error produced by that validation, before yielding, with owned
POLICY and confirmed nonsuppressing cleanup may now clear the nonce. Entry,
body, COMMIT and cleanup uncertainty still retain it. Negative tests include
an external error with identical text and errors after yielding.

The other failures were isolated fixture premises: the native fake returned
UNKNOWN without the required error reason; publication now creates actual
POLICY metadata before claim tests. The revised fixtures retain real SQLite
transactions, original allocation/uncertainty assertions and explicit synthetic
providers. They do not erase runtime binding to force a pass.

The private runner loads these unittest modules in the clean export (equivalent
to the first command below), then executes the two PowerShell commands. The
runner itself uses the daily `invoke-sentinel.ps1` admission wrapper:

```text
python -m unittest tests.test_adaptive_legacy_writer tests.test_adaptive_legacy_native tests.test_adaptive_managed_publication tests.test_adaptive_managed_admission tests.test_adaptive_registration_publication tests.test_coordinator tests.test_adaptive_coordinator tests.test_adaptive_ledger_coverage tests.test_adaptive_execution_owner tests.test_adaptive_control_authority tests.test_adaptive_s1_owner_integration tests.test_adaptive_admission_context tests.test_adaptive_job_scope tests.test_adaptive_finalization_restore tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch tests.test_adaptive_evidence_scope tests.test_adaptive_accounting tests.test_adaptive_policy_scope tests.test_adaptive_exemption_sync tests.test_adaptive_control_slot tests.test_exemptions tests.test_adaptive_native_cancel
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_exemption_policy.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_legacy_mutation_adapter.ps1
```

Final additional-test verification: `python -m unittest tests.test_adaptive_job_scope`.
The 23-test run overlaps the full run; these are not 540 unique tests.
The actual new legacy native/Job setters use explicit synthetic fixtures here.
Existing native self-identity/cancellation checks use only their owned isolated
process/data scope. No native test Job, cap or Scheduled Task was created; no OS
restriction needs withdrawal. This does not pass S1/S2/S3 or P5 native control.

Post-run verification found all three exact test reservations released, the 35
monitored daily source paths unchanged, daily configuration unchanged, and index
source/test bytes identical to the final tested export. The incoming dirty
collector/wrapper/coordinator content remains working-only through narrow patches.
Private raw logs, hashes and preservation copies stay out of the repository.

## Next actual implementation gate

S1's entry currently lacks a real continuous host-authority provider and bounded
native machine sampler. Recovery also lacks the consumer that verifies all owned
caps restored, reconciles accounting and observes five fresh uncapped samples
before clearing RECOVERY_HOLD. These are implementation gaps, not failed Windows
API results. The restore callback runs inside locks; the sample collection must
run outside them before a final revalidated CAS.

Separately, tested Codex/Scheduled-Task/Explorer-dispatch/CI launch paths were
observed inside a foreign Job with an unknown denominator. That is a host support
boundary. It does not establish that Windows lacks Job-list or CPU cap APIs.
Production launcher/guardian/helper and P4–P6 remain unverified and off.
