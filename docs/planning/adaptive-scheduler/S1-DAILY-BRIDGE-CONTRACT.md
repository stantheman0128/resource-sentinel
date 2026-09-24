# S1 native producer: daily accounting bridge

## Approved implementation deviation: explicit test demand lifetime

The implementation coordinator accepted an explicit, narrowly test-only
`DailyExperimentDemand` contract on 2026-09-22. It references the **same actual
daily reservations row** and adds lifecycle metadata; it does not create a third
capacity reservation store. This uses the allowance for additive lifecycle
metadata in formal plan §7.2 and preserves the floors required by §§7.1 and 7.4.
It is test-verification integration, not runtime deployment or promotion.

This is an explicit addition to the formal plan's test plumbing. Two existing
paths cannot supply it unchanged. A normal daily native umbrella Job places the
spike host under a parent Job, contradicting S1's unrestricted-host preflight.
An unnamed ManagedAdmission kept RESERVED does retain demand, but its replay
never renews a lease; TTL changes it to UNCERTAIN_HOLD. Existing cancel_reserved
permits only a genuinely unused launch with no Job, guardian, workload or
handoff. It cannot silently become an isolated-work completion API.

The new metadata must distinguish the unused daily launch credential from the
isolated experiment that actually executes. Atomic admission and every retry
bind the original native caller, source generation, actual ledger identity,
reservation, declared demand, experiment identity and immutable isolated-scope
description. It must not mint a second request after lost acknowledgement.
Grace, TTL, wrapper death and missing responses retain the global demand floor.
No API exports the daily launch credential for isolated execution.

The first implementation slice is exact atomic admission metadata and its
retained original operation. Subsequent native binding must retain the original
sealed creation registry for **all** test infrastructure and workloads before
side effects, plus original handles/transport operations after uncertainty.
Retirement requires the genuine original completion capability: caps disabled,
children empty, correct isolated terminal proof, native owner cleanup and fence
cleanup. Serialized records, callback booleans or historical receipts alone
cannot mint it. An expiry-only hold may be retired only by that new exact proof
path; it must not reset RESERVED, extend the elapsed lease, fake FINISHED, or
weaken the existing production C2 requirement last_applied=None.

Ordinary admission and production CPU authority remain unchanged. The provider
continues refusing native experiments until the entire lifetime, loaded-writer
exclusion and cleanup bridge is wired and verified. Root owns integration of
shared Coordinator/lifecycle/operator hunks and all test execution.

The first source slice uses `DailyExperimentDemand.capture(declaration,
isolated_directory)` and `Coordinator.admit_experiment(original_owner)`.
Capture does not admit or launch work. Admission reads the canonical daily
`config.json` and `status.json`; the public experiment route accepts no caller
status, configuration override, clock, alternate ledger, or readiness callback.
The exact current generation must positively prove readiness before the shared
capacity transaction. SQLite publication creates the ordinary managed reservation
and the immutable `adaptive_experiment_demands` binding atomically. This metadata
has only `ADMITTED` revision zero in this slice; every row blocks retirement.
Its canonical table and trigger definitions are checked even when it is empty.

The durable triggers retain the reservation and its identity/resources and
forbid consuming the unused daily claim. Normal TTL cleanup may still change
`RESERVED` to `UNCERTAIN_HOLD`; it cannot lower requested or allocated floors,
associate a Job/root, terminalize the row, or delete demand. Lost commit ACK
keeps the same original managed owner and POLICY operation for exact readback
and settlement. Failed readiness or uncertain connection/native cleanup
quarantines the original objects; retry cannot replace them. Only an owner
that never submitted demand and has positively settled preparation can close
its unused native caller. There is no admitted-demand release API yet.

These source APIs remain unusable as a native experiment provider until the
creation/exclusion/exemption/floor-growth/cleanup bridge is complete. The
`require_native_scope()` refusal is deliberate; admission alone is not launch
or CPU control authority. The portable fixture tests model generation readiness
explicitly and cannot establish an activated daily generation or a native gate.

Status: source integration contract, **not** capability evidence. No daily
configuration, database, Scheduled Task, or native control was changed to prepare
this document. The producer remains blocked at `require_continuous_admission()`.

## Next source slice: one original S1 native scope

The implementation coordinator approved the next bounded slice on 2026-09-22.
It is one explicitly test-only S1 scope, not a production control permit or a
general adapter for the old `S1Runtime`. Its original guardian owns the native
Job and is the only CPU actuator. A separately created, authenticated test
wrapper owns its original command launch; guardian, wrapper and started root
identities remain distinct. No workload is relabeled as infrastructure.

The slice requires these concrete pieces together before the S1 producer can
use it:

1. An original `DailyExperimentDemand` remains the sole real capacity source.
   The native scope pins the same reservation, generation/source/config and
   ledger file identity. The isolated test ledger contains native scope,
   intent, slot and cleanup records; it does not admit a second reservation or
   supply machine capacity measurements. An expired or uncertain daily lease
   closes new work/control but retains the full floor and restore obligation.
2. A bounded daily experiment-exclusion registry records exact test actors and
   the original retained Job name/nonce. Registration and source-generation
   readiness must reach the loaded daily legacy writer. Its actual POLICY
   registry read merges those actors/Jobs and its actual native membership
   query excludes all descendants. A registry row alone grants no native
   custody. A test Job must be originally created and successfully registered
   before any contained command can start; an uncertain registration prevents
   launch and retains the original Job. Query-only handles belong to the
   legacy writer; they never borrow ownership of the guardian's numeric handle.
3. Restrictive operations explicitly acquire **daily POLICY → isolated POLICY
   → exact Job mutex** at their outer entry. No SQLite transaction spans a
   native wait, query, Set, another ledger, or an RPC. Existing
   `S1ControlAuthority.authorize_control` runs too late to acquire daily POLICY
   and is not an integration shortcut. The final grant read uses the actual
   daily `ExistingPolicyStore` and adjacent daily `exemptions.sqlite3` under
   the retained daily guard, which remains held through Set/query/settlement.
4. A grant committed before Set rejects the restriction. A grant committed
   after Set is observed by the actual owning guardian and withdraws the cap
   from the entire original Job. Unknown applicable scope is conservative.
   Public grant authorization, original deadlines and the three-lease cap stay
   unchanged; `restore_pending` is not an OS acknowledgement. Neither polling
   cadence nor portable tests establish the two-second recovery target.
5. Restore of the original owned cap can run under isolated POLICY → Job when
   daily readiness, grant reads or daily locking fail. Such a path permits no
   new restriction or renewal. Lower capped usage never reduces daily demand.
6. Cleanup produces a distinct, original retained native-registry completion
   capability only after launch is sealed, the correct test terminal state is
   known, caps are queried disabled, Job membership is empty and every original
   actor/Job/transport/lock owner is positively settled. Uncertain creation,
   Set, publication, cleanup or ACK retains those same originals. JSON,
   callbacks, PID reopen, TTL, missing rows or closed handles cannot mint that
   capability. Its eventual daily retirement transaction may truthfully cancel
   the **never-exported, never-consumed daily launch claim**, while separately
   recording the completed experiment obligation. Ordinary production C2 and
   its `last_applied=None` invariant remain unchanged. The schema and retirement
   inventory must be coordinated before adding any `RETIRED` state.

The actual guardian/fixture bootstrap and canonical production imports are part
of this provider's implementation, not an assumed wrapper callback. Its source
closure must be explicitly pinned and reviewed. A distinct daily activation or
readiness keeper is not the test caller or isolated supervisor merely because
their metadata has a role label. Any later aggregate observer must retain the
actual native keeper witness before fixture creation, authenticate the pinned
generation/readiness endpoint, and charge that process separately unless exact
native identity proves a legitimate cohosted role.

This approved contract is implementation scope. It is not a measured native
result and does not unlock `require_continuous_admission()` by itself.

### Original-scope source slice (not yet a native gate)

The new `experiment_scope.py` owner and isolated `experiment_scope_journal.py`
implement original native custody for one S1 Job. The corresponding explicit
fixture closure is `adaptive_scope_launch.py`, `adaptive_scope_wrapper.py`, and
`adaptive_scope_cpu_worker.py`. This test guardian directly owns the existing
`NativeJob` mechanism and uses the existing `native_launcher.launch_in_job`
inside its distinct authenticated wrapper. It does not pretend to be a
production `GuardianLaunchOwner`, enroll an isolated reservation, or provide a
production S1 capability receipt. The previously described production-owner
integration remains a separate prerequisite for S2/S3 and subsequent phases.

The implemented native scope performs the following concrete operations:

- Prove its original daily reservation before creating the test listener;
  create its empty test Job and inert wrapper under daily POLICY, isolated
  POLICY, then the original Job mutex; publish the exact exclusion before any
  workload launch. The actual daily legacy writer reads that exclusion.
- Persist isolated launch/control intents and apply only the explicit S1
  2,500-basis-point cap. Recheck the original lease and experiment deadline
  immediately before Set. Actual bound daily grants deny a new cap; the owning
  guardian's observation path restores the whole Job after a grant or loss of
  readiness. Legacy grant ancestry without exact native identity is treated
  conservatively. An unbound exemption store refuses control.
- Restore from the original native owners without requiring the daily database,
  source readiness, or a valid lease. Exact original/last-applied/pending CPU
  states bound the recovery write; an external CPU setting is not overwritten.
- Reconcile a registration acknowledgement against the same original Job and
  wrapper, and distinguish authenticated noCreate from an originally retained
  root. `SEALED_UNCREATED` is isolated test bookkeeping and never resets the
  production lifecycle or changes ordinary C2.
- Preserve separate actor-close, Job-close and mutex-close checkpoints. A
  positive native completion capability requires sealed launch, zero members,
  disabled CPU control, settled original transport and native owners, and
  completed original POLICY cleanup. Known wrapper Create failure can close
  its original empty Job without inventing a wrapper or journal identity.

The source still has concrete integration limits. The current core requires
the genuine original in-process `DailyGenerationOwner`: the existing remote
readiness call cannot run inside POLICY, so an external-console provider needs
an authenticated pre-lock readiness owner with retirement-race semantics.
Unknown native Job construction or ambiguous pipe/close outcomes retain the
original owners and demand; these are not positive cleanup. The immutable
daily cleanup/retirement receipt, truthful never-exported claim cancellation,
historical validator, and serial S1 producer adapter are not yet wired. In
particular, `NativeScopeCompletion` by itself does not release capacity, change
the daily mode, satisfy P1, or enable `require_continuous_admission()`.

All new control and cleanup tests use isolated SQLite and explicit synthetic
native collaborators. They are source verification only; no new native gate,
daily activation, runtime configuration change or production control is claimed.

Central verification on 2026-09-24 passed **303 tests in 19.533 seconds, zero
failures/errors/skips**. Review found and corrected two concrete boundaries:
both wrapper and workload Create now check the original absolute scope deadline
after preparation, independently of a later RPC deadline; wrapper bootstrap
compiles the exact verified fixture bytes and validates complete canonical import
provenance. Nine isolated base-Python subprocess tests include a real
timestamp-valid stale `.pyc` and a stale production module initializer. These
subprocesses acquire no native Job or capacity authority.

The initial 255-test foundation run had three errors in a fixture that requested
zero CPU/RAM. It now uses valid .1 CPU/128 MiB demand and the real admission
checks; the ten-Job limit assertions are unchanged. The subsequent 263-test core
run passed before the final 303-test bootstrap integration. All runs used normal
daily P2 HEAVY admission and isolated test ledgers. Complete private evidence is
`.local-adaptive/original-scope-integration-20260924-1.log`; the protected dirty
baseline and adjacent uncommitted additive readiness primitives remain test
dependencies. Consumer wiring for those readiness primitives is unverified.

```text
C:\Python313\python.exe -m unittest tests.test_adaptive_experiment_scope_journal tests.test_adaptive_experiment_exclusion tests.test_adaptive_scope_cpu_worker tests.test_adaptive_scope_launch tests.test_adaptive_scope_bootstrap tests.test_adaptive_native_launcher tests.test_adaptive_legacy_writer tests.test_adaptive_legacy_native tests.test_adaptive_experiment_demand tests.test_adaptive_experiment_scope -q
```

This source slice does not assemble the aggregate provider's canonical fixture
module bindings, release daily admitted capacity, make the experiment exclusion
reusable, or provide later S2/S3/P4/P6 execution evidence. Those remain explicit
source and execution dependencies.

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
| Native runner imports | Current runners under the implementation worktree put that worktree on `sys.path`; daily activation attests canonical production modules and does not copy `tests`. | Add a narrowly reviewed, pinned fixture-package/bootstrap source closure that imports canonical production code. Never copy the whole test tree or claim the current worktree command proves activated daily consumption. Keep A0 baseline source separately pinned and disclose any changed outer accounting behavior. |
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
