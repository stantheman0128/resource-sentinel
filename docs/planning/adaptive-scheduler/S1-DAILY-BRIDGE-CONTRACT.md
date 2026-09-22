# S1 native producer: daily accounting bridge

Status: source integration contract, **not** capability evidence. No daily
configuration, database, Scheduled Task, or native control was changed to prepare
this document. The producer remains blocked at `require_continuous_admission()`.

## Two independent authorities

The original daily accounting owner obtains all capacity from the actual daily
provider and retains the complete declared experiment demand until positive
cleanup. A separate isolated test data directory contains the test guardian,
lifecycle/control state and test mode. That test database never grants capacity,
supplies host measurements, renews the daily reservation, or releases the daily
demand floor. It is not an alternative admission source. Daily adaptive stays off.

The original daily owner must survive a lost admission or cleanup acknowledgement.
A response, manifest, PID, environment variable, or row copied to another database
cannot replace it. Keep the actual ManagedAdmission, launcher, transport operation,
native handle, and retained fence that participated in an uncertain attempt.
Reconcile that attempt instead of creating another reservation or wrapper owner.

Use a separate authenticated test guardian and test wrapper. The guardian's
original GuardianLaunchOwner retains its wrapper, Job, per-execution mutex, root
if created, and every partial native owner. GuardianLifecycle._manifest requires
three distinct process identities after launch; GuardianLaunchOwner._authenticate
rejects a wrapper that is the guardian. Duplicating handles does not change the
identity. Simply renaming the current same-process S1 Test.Job is insufficient.

DailyGenerationOwner.assert_ready or its native authenticated service proves the
installed source generation and cohort condition. It does not enroll a test
guardian, create demand coverage, or authorize CPU control. The daily bridge also
needs actual infrastructure/Job exclusion and original demand coverage. Isolated
HostAuthority reads can establish test lifecycle consistency, but cannot replace
those daily proofs.

## Conservative cross-ledger order

1. Positively obtain and retain original daily admission for the complete bounded
   experiment, including wrapper, guardian, helper and workload demand. Publish
   durable daily accounting before a test operation can create work.
2. Create the isolated test scope under its authenticated guardian. Bind both
   sides to immutable run/scope identity and the original daily reservation.
   An isolated row or acknowledgement alone never authorizes further launch.
3. Keep daily coverage through Set, measurement, restoration, root exit,
   surviving children, failed RPC and native cleanup. Expired lease or lost
   heartbeat closes new work but must not erase the demand floor.
4. Withdraw the exact cap and positively query disabled, settle its intent,
   prove Job empty and the correct terminal state, close all original native
   owners, then complete retained POLICY/transport cleanup.
5. Release daily demand exactly once only when its original accounting owner
   has that complete result through the authenticated original bridge. Lost
   final acknowledgement retains the same owner for reconciliation; it never
   repeats launch or infers release from an absent row.

There is no SQLite transaction spanning both ledgers. The implementation needs
durable operation identities and this conservative ordering: daily capacity
first, isolated native activity second, complete native cleanup before daily
release. Every interrupted edge retains capacity and the exact original
operation. A boolean callback or signed-looking JSON report is not the bridge.
The actual abnormal-cleanup lifetime owner is still a missing implementation seam.

## Test-only S1 control

The bootstrap binds once to one original guardian-owned experiment scope and
pins the native Job, wrapper/guardian identities, reservation, specification
hash, nonce, epoch, source generation, daily ledger file identity, and an absolute
monotonic deadline of at most 120 seconds. A failed bind cannot restart the
deadline or swap an owner. It does not create a production capability receipt.

Only the explicit 2,500 basis-point S1 Set is eligible. Do not invent CPU HIGH,
fabricate a policy recommendation, or require successful S1 evidence to run S1.
Before Set, positively verify daily demand, native empty/contained scope, actual
old-writer exclusion, applicable exemptions, the single isolated control slot,
and current baseline under POLICY then the canonical Job mutex. Persist intent
before native Set, Query its result, then persist acknowledgement. Isolated slot
state must not write daily mode or daily control state. The daily owner retains
declared demand while usage is suppressed; lower usage never expands admission.

After Set may have run, restore is independent of new admission and readiness.
Use the original Job and exact original/last-applied/pending-intent comparison.
Deadline, feature-off, root exit, lost ACK and handle close do not prove Job
empty or capacity released. Unknown close results retain quarantined owners.

## Concrete source gaps

| Area | Current evidence | Required resolution |
| --- | --- | --- |
| Original S1 scope | S1ExecutionOwner uses Test.Job, TestRecoveryJournal and the same caller for wrapper/guardian. | Separate authenticated guardian-owned fixture path; preserve identity invariants. |
| Daily source readiness | Native source-generation readiness exists, without an enrolled S1 guardian/admission owner. | Assemble actual retained daily accounting and legacy-exclusion owners; no readiness boolean unlock. |
| Lifetime bridge | S1Runtime submits directly to one Coordinator/lifecycle store; no original owner spans daily demand and isolated cleanup. | Implement the ordered dual-authority bridge, including crash/lost-ACK retention and exactly-once daily release. |
| Daily off | control_slot.begin_locked accepts only canary/limited. | Test mode/control state stays isolated. Preserve daily mode check and C2 invariants. |
| Legacy exclusion | Daily HostAuthority.assert_excluded requires a canonical scope in its own registry; isolated test rows are not there. | Establish an authenticated exact test-scope handoff recognized by loaded daily writers. Expected rejection and source hashes alone prove no exclusion. |
| Shared history | Old S1Recovery requires the entire managed table to equal at most 64 test owners and directly writes the global barrier. | Independent bounded keyset scanner, genuine foreign closure receipts and public C3 API respecting off generations; never a substitute for the dual-authority bridge. |
| Empty-restore | S1 caps/restores a never-associated Job; correct terminal state is CANCELLED_BEFORE_START. Production C2 requires last_applied=None. | Keep daily C2 unchanged. Isolated S1 must prove total-process count zero, root absent, sealed launch, settled intent, disabled control and restored-slot recovery. No fake FINISHED or dummy launch. |
| C2 post-close history | C2 atomic retirement receipt exists, but pending cleanup closes owners without a durable post-close receipt; historical custody accepts FINISHED only. | Independent historical custody gap. Never confuse a C2 accounting receipt with actual native cleanup or change daily C2 to pass S1. |
| Empty probe slot | Supervisor historical RESTORED-slot path accepts FINISHED only. | Isolated protocol retains the original empty-probe owner until exact cleanup settles; unknown custody stays blocked. |

## Bounded source work

adaptive_capability_runner.py produces fixed-window raw S1 observations and
immutable bundles. Incomplete cleanup retains original coverage and safe OS
error codes without exception text. Infrastructure membership borrows the
original admission process witness instead of opening an unnecessary handle.

adaptive_spike_inventory.py is a separate bounded shared-ledger scanner, not a
launch/control authority. Its completed snapshot pins registry/runtime; foreign
history needs genuine terminal custody. It refuses legacy TestRecoveryJournal
and unknown C2 post-close history. Its C3 clear uses the lifecycle API rather
than assigning admission_barrier=NONE directly.

Portable tests establish these source boundaries only. Root-owned verification
must use actual daily admission. No synthetic result establishes a Windows gate.

## Portable verification, 2026-09-22

The central admitted run covered capability producer, S2 producer, inventory,
P4 overhead and S3 foundations: **161 tests passed in 41.676 seconds, zero
failures/errors/skips**. The first 144-test run had two inventory fixture errors:
the caller held POLICY but had not begun the SQLite transaction required by
`assert_current_locked`. The fixtures now open that transaction; production
requirements were preserved. A preceding 344-test provenance integration run
also covered the capability producer's 21 tests.

These tests use the protected dirty integration baseline and adjacent source
work; they are not clean-clone, native measurement or runtime activation proof.
The real daily demand/isolated cleanup bridge remains unimplemented, so no
producer prerequisite is marked satisfied by this commit.
