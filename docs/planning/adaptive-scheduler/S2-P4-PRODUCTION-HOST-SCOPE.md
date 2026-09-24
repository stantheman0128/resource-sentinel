# S2/P4 isolated production-host scope

Status: **implementation contract; no native authority or passing gate is created
by this document.** Baseline: implementation commit
`12ce5e4a1ecaf99c1b7883960e8510d0d298df73`, 2026-09-24.

This contract connects the existing S2 and P4 producers to actual production
hosts while retaining one original daily admission for the complete experiment.
It implements the ownership requirements in the formal plan §§3.2–3.3, 4.5,
7.4–7.5, 8.4, and 12. It does not change the plan's ordered gates, authorize a
daily deployment, or activate production adaptive control.

## 1. Existing authority and the missing connection

`DailyExperimentDemand.capture()` pins the original daily ledger, source
generation, declared demand, caller identity, and original `ManagedAdmission`.
The existing S1 `ExperimentNativeScope` and `NativeScopeCompletion` are exact
original-owner types for one `Local\\ResourceSentinel.Test.Job.<nonce>`.
They remain unchanged; S2/P4 must not masquerade as that scope or mint its receipt.

`SupervisorHost`, `GuardianHost`, `WrapperHost`, `GuardianLaunchOwner`, and
`ManagedLauncher` already perform real creation, authenticated launch, retained
identity, and retirement work. Their ordinary `HostAuthority` intentionally
checks the same ledger. An isolated `Coordinator` with copied config/status does
not prove that the daily machine ledger covers those processes, and an isolated
legacy registry does not control the daily collector's writes.

The missing component is an **original aggregate experiment owner** with a
bounded daily capacity partition, authenticated child bindings, and publication
to the daily legacy exclusion registry. This is a specific test-only integration
capability, not a configurable authority callback or alternate machine budget.

## 2. One machine reservation, bounded isolated partitions

The original daily reservation remains the sole machine admission for the cohort.
It retains its complete declared `ResourceDemand` until the aggregate completion
and original cleanup operation positively settle. The 58 GiB total-machine
budget, 4 GiB physical reserve, 4 GiB Commit reserve, and three exemption limit
are unchanged. No automatic exemption is added.

Define a fixed infrastructure slice and explicit per-execution slices using the
existing units: `cpu_units`, `physical_bytes`, `commit_bytes`, and `io_slots`.
For each component, before new work is authorized:

```text
infrastructure slice
  + all live, reserved, creation-unknown, or retirement-unsettled partitions
  + proposed new partition
  <= original daily requested demand
  <= positively retained original daily allocation floor
```

The infrastructure slice includes the resident supervisor/guardian/helper,
driver, telemetry/observer threads, listeners, and bounded bootstrap overhead.
Per-execution slices cover the wrapper, root, and descendants. Attribution must
be explicit so a process is not omitted or assigned capacity from two slices.
Demand must be honest for the actual cohort; a small synthetic status file is
not a way to fit a larger experiment into the original reservation.

The isolated lifecycle rows keep their real reservations, immutable specs,
claim tokens, and state transitions. Their new typed parent binding identifies
which already-admitted daily slice backs them. Admission of these rows consumes
that partition instead of independently re-evaluating a second 58 GiB machine
budget from isolated config. Ordinary isolated or daily admissions retain their
existing behavior. The experiment path cannot be selected by a caller-supplied
boolean, data-directory choice, or unverified parent ID.

Measured usage, cap-induced usage reduction, root exit, TTL expiry, process-handle
closure, or a local terminal row do not return a partition. A partition can be
reused within the still-reserved aggregate only after exact retirement and all
original custody for that attempt have settled. This does not shrink the daily
floor. Conservative double accounting with actual machine usage is preferable
to unproved subtraction; adding isolated projections must not create capacity.

## 3. Additive durable records and strict validation

Use new versioned aggregate records instead of broadening the existing S1 record
shape. The following are logical tables; final SQL must have strict shape/type
checks, exact schema/trigger verification, original-operation write authority,
and inclusion in the existing bounded history validation. No third database is
introduced.

| Daily record | Required immutable binding and mutable state |
| --- | --- |
| `adaptive_experiment_cohorts` | Original experiment/daily execution/reservation IDs; suite exactly S2 or P4; declaration hash; source generation and digest; daily ledger identity; isolated canonical ledger path and file identity; isolated POLICY instance/logon; scope nonce; original owner identity; requested demand and fixed infrastructure slice. Phase/revision are CAS-protected; sealing forbids all new creation. |
| `adaptive_experiment_partitions` | Cohort ID, operation/request ID, isolated execution/spec/admission binding, exact requested slice, and wrapper identity. Pending intent precedes creation/isolated admission; states distinguish reserved, creation entered/unknown, bound, retiring, and positively settled. Never reset an uncertain attempt to unused. |
| `adaptive_experiment_actors` | Cohort ID, actor/creation attempt ID, fixed role, parent exact identity, original creation provenance, exact actor identity when known, and protected phase. An unresolved bootstrap intent is represented explicitly; PID absence cannot complete it. |
| `adaptive_experiment_job_scopes` | Cohort/partition ID, production execution ID where applicable, exact Job name/nonce/logon, creating guardian identity/epoch, wrapper identity, isolated manifest binding, kind `managed` or `query_fixture`, registry revision, and terminal/cleanup digest. Exclusion persists through rollback and surviving children. |

The isolated managed row's typed backing record contains only references and
digests to the exact daily cohort/partition and original isolated reservation.
It does not copy the daily allocation into the isolated ledger or become
independent admission authority. A valid ordinary local reservation plus an
unrelated daily cohort is insufficient.

Every transition validates both the immutable binding and expected revision.
Different payloads cannot reuse an operation ID; duplicate exact operations are
read-only reconciliation. Bounds must be enforced before materializing large
inventories: one original aggregate preparation per demand, the plan's enrolled
Job limit, fixed actor/case cardinalities from the declaration, and existing
history size limits. Unknown versions, missing records, aliases, malformed
bindings, or partially missing triggers deny new work rather than regenerate
authority. Existing S1 schemas and history versions remain valid as themselves.

## 4. Native fences and bootstrap ordering

The actual process performing a guardian operation acquires its own verified
**daily POLICY → isolated POLICY → per-Job mutation mutex**, in that order.
This is not a parent holding a mutex while asking a child to execute over RPC.
Acquire fresh daily readiness/source-generation scopes before these locks;
validate the already-acquired scopes and exact durable binding at the protected
operation boundary. The ordinary authority remains the default.

No SQLite transaction spans a native call, another ledger's transaction, an
RPC, or a wait. Each ledger has a short local transaction. Durable pending
records bridge failures between them: commit a daily partition/publication
intent, release its SQL transaction, perform/reconcile the exact isolated
transition, then commit the daily acknowledgement. Missing acknowledgement
retains the partition and exclusion; it does not authorize another launch.
There is no cross-ledger transaction or distributed mutex handshake.

Before the first host/driver Create, the original aggregate owner registers and
retains the pending attempt. Every infrastructure child starts in a fixed inert
bootstrap: it may authenticate and wait, but cannot start hosts, workload, or
policy sampling until its exact creation identity is protected in the daily
registry and its concrete role is released to run. This is cooperative bootstrap,
not `CREATE_SUSPENDED`, breakaway, or periodic Suspend/Resume.

Hold the actual daily POLICY around the bounded Create/identity/publication
sequence, with no SQL transaction open during Create. Persist a bootstrap intent
before entering Create. An identity-unresolved or outcome-unknown intent makes
the daily legacy mutation reader refuse writes that it cannot safely exclude;
it must not leave an unprotected actor window after releasing the mutex. Do not
wait for child RPC while holding POLICY. The returned original creation handle
is the identity source; reopening a PID after a fast exit is not equivalent.

Before a command Job is created or published, register its exact name/nonce and
manifest intent in both scopes under the ordered fences. Before claim/Create,
revalidate the backed partition and publication. The new aggregate reader must
teach the daily legacy batch to skip every registered actor and Job for priority,
I/O, trim, and legacy/exemption restore. Unknown membership means no mutation.
Inherited priority is recorded, not silently reset.

## 5. Concrete owner and child API boundary

The following names define the intended seam, not currently available APIs:

```python
scope = ProductionExperimentScope.prepare(original_daily_demand, declaration)
scope.start_hosts()                 # owns attempts before every native Create
binding = scope.bind_child(peer, role, original_creation)
scope.reserve_partition(request)    # fixed typed request, no raw command/env
scope.publish_job_scope(request)    # exact partition + manifest/Job binding
scope.accept_retirement(request)    # evidence input, never a cleanup boolean
completion = scope.retire()         # original-owner completion or retained error
original_daily_demand.prepare_release(completion).release(original_coordinator)
```

`prepare()` accepts the exact original `DailyExperimentDemand`, checks S2/P4 and
the predeclared scope digest, and registers its custody with that owner. Failure
after entry retains the partial original. It must not reopen another demand
from a serialized snapshot.

The authenticated child binding pins peer PID/FILETIME/logon using retained
handles, the parent endpoint/instance, source generation, both ledgers, role,
cohort nonce, and request domain. Reuse the existing native pipe peer pinning,
challenge/MAC, deadlines, and uncertain cleanup ownership. No credential is
sent before verifying the server. Fixed operations authorize only the declared
child/partition; there is no generic callable handler or arbitrary source path.

The binding lets the actual guardian acquire and validate the daily native
POLICY itself. The broker never lends remote mutex ownership or hands out an
expiring receipt interpreted as a held lock. A child binding is not an original
daily cleanup capability and cannot release the umbrella reservation.

The new typed `ExperimentBackedHostAuthority` combines the existing exact local
allocation/identity checks with the daily partition and exclusion checks. Connect
it explicitly at `GuardianHost`/`GuardianLaunchOwner` and `WrapperHost` admission
and readiness boundaries. Service entry must establish the outer daily scope
before existing code enters isolated POLICY. A wrapper must not hold either
POLICY while waiting for guardian IPC. Parent/child protocol construction and
cleanup failures remain owned by the originals, including exceptions carrying
native, pipe, SQL, or identity cleanup owners.

## 6. S2 and P4 consumers

S2 uses the real `SupervisorHost` creation/retirement machinery, guardian launch
service, and instrumented real `WrapperHost`. The console driver and baseline
wrapper are also aggregate actors; their direct `Popen` entry cannot bypass
pending creation custody. Authenticated guardian AUDIT records showing exact
execution retirement are required, but do not close the driver's original
creation handle or establish whole-cohort completion. Semantic baseline
containment remains distinct from P6 A0 equivalence.

P4 implements the existing `coverage.open_overhead_session(jobs, directory,
profile, query_only_stress)` consumer. Its session exposes the actual retained
daily monitor and these fixed operations: `assert_daily_coverage`,
`read_guardian_set_audit`, `read_resident_telemetry`, `enter_idle`, `enter_stress`,
`prepare_wrapper_trial`, and `retire`. Successful checks return no fabricated
permission token; all cleanup authority remains in the aggregate owner.

The P4 producer must run with the **original `OperationalHelperHost` in its own
process**. `P4Producer._open` checks helper PID equality and
`NativeHelperHostSampler` verifies the exact started production host, sampler,
listeners, telemetry, and methods. A parent-side mock sampler or unrelated
remote helper does not meet this contract. Cohost the producer with that retained
helper and keep supervisor/guardian in their separate failure domains.

For the 50-Job observer measurement, there are at most **10 enrolled managed
Jobs plus 40 query-only fixture Jobs**. All 50 and all their actors remain within
the original capacity partition and daily legacy exclusion. The extra 40 have
explicit fixture scope records, verified native query handles, original creation
custody and cooperative retirement; they have no managed lifecycle row, launch
authority, control slot, or CPU Set eligibility. The legacy reader must separate
its broader measurement exclusion inventory from the 10-enrolled gate instead
of either silently truncating it or raising the production enrollment limit.
The shadow measurement must still prove zero restrictive control writes.

## 7. Settlement, recovery, and original completion

Fresh admission is required for new work, not for safety withdrawal. Retained
owners can compare-and-restore their own positively matched controls using the
existing native fences even when daily readiness or storage is unavailable.
They keep accounting and exclusion unresolved until storage reconciles. No
failure path tightens a cap, frees a live allocation, or releases another scope.

Aggregate retirement first seals all new actor/partition/Job creation. It then
uses authenticated guardian retirement plus original host/launcher custody to
prove each workload sealed, disabled and empty, each actor positively exited or
never created, and every original native/pipe/thread/SQL owner positively closed.
Root exit, an empty registry, a RESTORED slot, or one terminal ACK is insufficient.
Retire the actual `SupervisorHost`, including retained guardian/helper creation
handles and all its pending/unknown collections. Do not reconstruct that host
from status JSON to retry cleanup.

Add an exact new `ProductionScopeCompletion` type and a distinct version/domain
in `experiment_history`; do not accept an object merely because it has
`snapshot()`, `settled=True`, or the S1 receipt shape. It binds the original owner,
daily demand, declaration, both ledger identities, every partition/actor/Job
record and final revision, original creation outcomes, exact authenticated
retirement provenance, and cleanup custody. Its serializable snapshot is audit
data, not release authority. Size bounds apply to the entire completion.

Extend the original `ExperimentReleaseOperation` to accept that exact type and
atomically close the aggregate daily exclusion records, archive the original
daily allocation and completion, and advance the registry revision. The history
verifier covers the complete preimage/postimage, not only one convenient row.
On lost COMMIT ACK, only the retained original operation can verify/reconcile
the exact publication. Unknown rollback/close or native completion keeps custody
and prevents a second operation from inferring success. Ordinary rows and all
S1 records retain their existing contracts.

## 8. Connected implementation seams and exit evidence

| Seam | Concrete required change |
| --- | --- |
| `experiment_demand.py` and a new aggregate scope module | Whitelist the new exact original preparation type; bind the fixed infrastructure and execution partitions; own pending native attempts before creation. Keep `require_native_scope()` and S1 defaults fail-closed for unrelated callers. |
| Aggregate schema plus `experiment_exclusion.py`, `experiment_history.py`, `legacy_native.py` | Add versioned multi-actor/production-Job/query-fixture validation, daily exclusion consumption, bounded inventory, and original-operation mutation guards. Preserve the S1 schema/type rather than reinterpret it. |
| `Coordinator`/isolated admission seam and `host_authority.py` | Atomically bind exact isolated reservations to existing daily partitions; provide the explicit experiment-backed path without copied status becoming capacity authority. Ordinary callers remain unchanged. |
| `supervisor_host.py`, `guardian_host.py`, `wrapper_host.py` | Own inert bootstrap and original creation handles, authenticate the child binding, and enter the actual daily native POLICY before isolated POLICY/Job. Do not hold locks while invoking remote work. |
| `adaptive_launch_producer.py` and its child fixture | Consume actual aggregate actor/partition/publication operations for driver, baseline and managed cases; preserve original custody and authenticated retirement. |
| `adaptive_overhead_runner.py` / `adaptive_overhead_native.py` consumer | Implement the existing session contract around the cohosted actual helper, 10 managed plus 40 query fixtures, original telemetry, and complete retirement. |
| `experiment_cleanup.py` / history | Accept only the new exact original completion; validate and settle all aggregate rows in the original daily release operation. |

Before running the first real cohort, connected portable tests must exercise real
isolated SQLite records and original owner objects across admission → child
binding → publication → isolated lifecycle → retirement → daily release. Required
negative cases include over-partitioning; copied/foreign demand or ledger;
changed peer/spec/source generation; unregistered inert actor; unknown Create;
lost acknowledgement between ledgers; duplicate request with different payload;
root exit with a live child; missing exclusion; stale readiness blocking new work
while permitting restore; and partial native/SQL/pipe cleanup. Verify the daily
floor and exclusion survive every unresolved case.

Separately prove the P4 40 query fixtures cannot acquire managed launch/control
authority, the 11th enrolled Job is rejected, and the sampler consumes the real
cohosted helper. Receipt-shaped dictionaries and completion snapshots must fail
release tests. Portable tests do not establish native launch or overhead gates.

The first native invocation still requires a positively admitted original daily
demand, the supported active daily source/readiness generation, installed guarded
legacy writer, complete connected provider, and real host capability preflight.
The actual host may fail foreign-parent-Job, processor topology, affinity, API,
or recovery checks; this document supplies no exemption from them. Its missing
aggregate implementation is a source gap, distinct from those observed native
outcomes. Full S2 case counts, P4 durations/leak measurement, and subsequent
recovery/A/B gates remain the formal plan's exit evidence.
