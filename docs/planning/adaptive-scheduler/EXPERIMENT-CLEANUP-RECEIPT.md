# Original experiment cleanup receipt and daily demand release

Status: implementation proposal for item 5 of
[S1-DAILY-BRIDGE-CONTRACT.md](S1-DAILY-BRIDGE-CONTRACT.md), based on the source
following `ebd936c`. Names below marked **proposed** are not implemented APIs or
permission to release a reservation. This document changes no source, database,
runtime setting, policy or capability gate. Daily adaptive remains off.

The required result is one truthful daily cancellation after the original
isolated experiment has positively completed native cleanup. The daily claim
never launched anything: its reservation covered a separately executed test.
The daily execution therefore ends as `CANCELLED_BEFORE_START`, while the
separate experiment receipt preserves whether the isolated root ran, never
launched, or no wrapper was created. Neither outcome is production `FINISHED`.

## Existing source boundaries

| Source hook | Current behavior | Required addition |
| --- | --- | --- |
| `experiment_demand.DailyExperimentDemand.capture`, `_original`, `_static_original` | Retains the actual `ManagedAdmission`, native self witness, immutable declaration, daily ledger/directory identities and original request. The inner claim is private. | Retain and seal one original native-preparation registration; retain one release operation before any release-side acquisition. |
| `DailyExperimentDemand.publish_locked`, `_schema`, `admission_blocker_locked` | Atomically publishes immutable `ADMITTED`, revision-zero metadata alongside real daily admission. Strict triggers prohibit release. All historical rows currently occupy the single experiment position. | Preserve admission metadata; add verified completion history and count only positively unresolved experiments as occupying that position. |
| `ExperimentNativeScope.prepare`, `_retain` | Retains scope/native owners; partial `ScopeLaunch.prepare` ownership can survive on the original exception. There is no demand-owned registry binding every preparation attempt yet. | Bind this exact original scope to demand before preparation side effects; keep partial acquisition state reachable through demand and its error. |
| `ExperimentNativeScope.close_native`, `NativeScopeCompletion.assert_original` | Returns an original capability only after scope-owned actor, Job, mutex, SQL and retained fence cleanup. The digest binds the isolated terminal record and daily binding. | Consume this capability through the original demand; never reconstruct it from its digest or serialized terminal record. |
| `ExperimentNativeScope._close_uncreated_wrapper` | Positively handles pre-Create/documented Create FALSE with an original owned, never-used Job. It creates `WRAPPER_NOT_CREATED` evidence without inventing wrapper/journal/exclusion rows. | Accept this genuine completion as a distinct receipt variant. Do not turn every failed preparation into this branch. |
| `experiment_exclusion.register_locked`, `read_locked`, `assert_available_locked` | Publishes and consumes the original registered Job/actors. Readers require the live daily allocation. Although SQL mentions `CLOSED`, the supported reader/guards provide no close or reuse route. | Close the exact row in the release transaction and validate preserved closed history before excluding it from active native lookups. |
| `ManagedAdmission.cancel_reserved`, `Coordinator.cancel_managed`, `ManagedAdmission.close` | Explicitly reject `_experiment_demand`; ordinary cancellation covers a genuinely unused ordinary launch, not an executed isolated experiment. | Keep these guards. Add a distinct typed experiment release entry point; do not clear the marker, export a claim or call ordinary cancellation through a fabricated context. |
| `daily_retirement_inventory._schema`, `_read_ledger`, `_journal_inventory`, `_receipts` | Strictly bounds history, rejects experiment rows, rejects unknown adaptive tables, and expects production Job/journal custody for managed history. | Recognize the reviewed experiment schemas and validate their exact historical tuple through a separate branch. Preserve all production receipt checks. |

## The original owners and two completion paths

The following minimal API is **proposed**. These are exact concrete types with
private construction and original-object retention, not protocols accepting
user callbacks or duck-typed `complete=True` objects:

```python
# Before ExperimentNativeScope.prepare enters any preparation side effect:
scope = ExperimentNativeScope.prepare(demand, command, ...)
# Its original factory internally binds the new scope to demand first.

completion = scope.close_native()      # existing NativeScopeCompletion or None
operation = demand.prepare_release(completion)  # proposed retained operation
result = coordinator.release_experiment(operation)  # proposed exact daily route

# Alternative, only when native preparation was never entered:
completion = demand.seal_without_native()  # proposed BeforeNativeCompletion
operation = demand.prepare_release(completion)
result = coordinator.release_experiment(operation)
```

`prepare_release` seals admission replay, native preparation, launch and claim
handoff irreversibly, and pins the original completion object, experiment ID,
daily execution/reservation/request IDs, and release operation ID. Repeating it
with the same original capability returns the same operation. A different
capability, original owner, request ID, declaration, generation, ledger identity
or target is rejected. It never refreshes a lease or the 120-second native
scope deadline. Observation/export methods return data only.

The demand's preparation registration must be published before the first
`ExperimentNativeScope.prepare` side effect, including source/readiness/SQL/pipe
or native acquisition. Use the original factory and exact retained object; a
caller cannot register an arbitrary function or attest that preparation never
happened. At most one original scope/attempt can ever bind to this demand.

`BeforeNativeCompletion` is minted by the original demand only after it seals
that registry and proves preparation was never entered, the unused daily claim
was never exported/prepared/consumed, and all admission/preparation-independent
readiness, submission and connection owners have positively settled. This path
can cancel an admitted reservation without inventing native scope, wrapper,
Job, isolated terminal state or exclusion metadata. `close_unsubmitted()` keeps
its existing meaning for a context that never submitted; it is not this API.
Queued-only abandonment is a separate exact queue route and must not fabricate
an admitted reservation or cleanup receipt.

Once scope preparation begins, the before-native path is permanently
unavailable. A known source refusal, missing returned wrapper or failed factory
call does not undo that fact. The demand retains the original scope and every
partial constructor/connection/transport owner, including objects held on its
original exception. The existing Job-owning `WRAPPER_NOT_CREATED` branch may
produce `NativeScopeCompletion` after all of its actual cleanup. Failures even
earlier than that branch require an explicit original preparation-cleanup path
that accounts for every attempted acquisition before it can mint a completion;
the current `NativeScopeCompletion` cannot be assumed to cover them. Until
that path exists or positively settles, the reservation remains held.

For a created wrapper, completion requires authenticated launch sealing, the
actual root disposition, disabled original CPU control, no pending intent,
empty Job membership, the correct isolated terminal record, and closure of
every original scope-owned actor/Job/transport/mutex/SQL/fence owner. Positive
never-launched proof also requires lifetime process count zero. A documented
Create FALSE permits only its exact known-absent cleanup; an unknown Create or
unknown close retains the original owner and cannot mint a capability.

The demand's original self witness is borrowed by the native scope. It remains
live and owned by demand to authenticate the later daily operation; it is not
a surviving workload or an excuse to leave scope-owned witnesses open. The
release operation separately owns and settles its newly acquired daily POLICY
guard and SQL connections. A native completion cannot attest that these future
release-side resources are already closed.

## Immutable receipt content and durable representation

Add a bounded, append-only table, proposed
`adaptive_experiment_cleanup_receipts`, with one unique receipt per experiment,
daily execution and reservation. Keep the original
`adaptive_experiment_demands` row unchanged (`ADMITTED`, revision zero and the
same `binding_sha256`). That row records admission history; its active
obligation is resolved only by the entire verified completion/cancellation
tuple below, never by the presence of a receipt ID alone.

The original operation freezes a closed, versioned receipt before publication.
The receipt contains no credential, raw command or exception text. Its exact
schema must bind at least:

| Field group | Required binding |
| --- | --- |
| Identity and operation | Schema version, receipt/operation ID, experiment ID, suite, daily execution/reservation/request IDs, exact original caller PID/birth/logon, demand binding hash and declaration/scope hash. |
| Actual daily source | Canonical daily ledger path and file identity, source generation/source/config digests, admission binding/spec hashes, daily POLICY instance/logon. |
| Declared capacity | Original requested demand and the allocation/floor preimage actually validated for release. No cap-adjusted demand or zeroed historical floor. |
| Native disposition | Closed enum: `BEFORE_NATIVE`, `WRAPPER_NOT_CREATED`, `NEVER_LAUNCHED` or `FINISHED` **for the isolated experiment only**. Exact original completion digest; nullable scope fields are allowed only by the defined variant. |
| Scope evidence | When present: isolated ledger identity/path, scope ID, command hash, creation nonce, Job name, original guardian/wrapper/root identities, terminal record and its digest, original deadline, exclusion binding hash, settled intent/slot disposition and exact closed-owner binding. |
| Transaction binding | Daily pre-state/revision and canonical preimage hash; deterministic cancellation/archive postimage hash; prior/result registry revision; expected exclusion postimage or positive original no-registration disposition; fixed transaction time. |
| Integrity | Canonical domain-separated receipt digest over all preceding fields, with exact scalar types, enum validation, size limits and no unknown fields. |

The producer of the first durable row must hold the original typed operation
and completion and call `assert_original`; hashes and JSON cannot supply this
authority. SQL guards defend the reviewed state transition and correspondence
between rows. They cannot prove native execution on their own and are not
advertised as a hostile same-user SQL security boundary. No pluggable evidence
callback, environment switch, temporary trigger removal, global bypass flag or
private-guard mutation is part of the API.

An empty probe that applied/restored a cap can end isolated `NEVER_LAUNCHED`.
Preserve that isolated control history in the receipt. Do not manufacture
production `FINISHED`, a dummy root, a production recovery manifest, or a C2
receipt with invented `last_applied=None`. Ordinary production C2 retains its
existing `last_applied=None` rule unchanged.

## One atomic daily release transaction

Introduce a dedicated retained `ExperimentReleaseOperation` in a proposed
`experiment_cleanup.py`, constructed only by `DailyExperimentDemand`.
`Coordinator.release_experiment` must require its exact type, original demand
and actual daily Coordinator; reuse the retained submission POLICY/store and
its original-operation cleanup/reconciliation machinery. This is a new narrow
route, not a relaxed `cancel_managed` argument.

Before opening the writer transaction, settle original admission uncertainty,
validate native completion and immutable bindings, seal future work, and retain
the release operation. Acquire actual daily POLICY outside SQLite. All native
observations and isolated ledger reads needed to capture the completion occur
before `BEGIN`; readiness RPC also remains outside POLICY and SQL locks. This
does not exempt the transaction from existing exact generation/source/file
revalidation using its original retained authority. No new peer or workload
handle may be opened inside the transaction to reconstruct completion. The completion
is monotonic: after positive native close, no same original owner can create,
reopen, Set or launch again. Preserve its exact object through the transaction.

Under that same original daily guard, perform one `BEGIN IMMEDIATE` transaction:

1. Verify exact schemas and canonical trigger definitions, actual daily ledger
   binding, runtime mode `off`, original generation identity and demand hash.
   Accept cleanup during the same generation's `ACTIVE` or `DRAINING` state
   through the reviewed cleanup-only path; fresh admission/readiness and an
   unexpired lease are not cleanup prerequisites. Unknown/replaced generation,
   source or ledger remains a refusal. Do not disable the retirement fence.
2. Read at most the exact matching rows and reject aliases/conflicts. Verify
   the full immutable daily managed row and original direct reservation using
   the ordinary cancellation binding/allocation predicates as a baseline.
   The claim remains never-exported, unprepared and unused: no daily Job,
   nonce, root, guardian handoff, routed allocation or launch-in-flight; the
   stored original claim hash still matches; `claim_consumed=0` and
   `launch_sealed=0`. Demand/allocation/floors remain fully charged until commit.
3. Validate this operation's exact native completion binding against the
   immutable demand and, when registered, the exact exclusion row. A missing
   exclusion after uncertain registration is not the no-wrapper branch.
   Resolve the original registration outcome first. The before-native and
   original never-created variants require their positive original disposition
   plus no conflicting exclusion, not an absence query as native authority.
4. Insert the immutable cleanup receipt, compare-and-set the exact daily
   execution to `CANCELLED_BEFORE_START`, and invalidate the unused claim using
   ordinary terminal cancellation semantics (`launch_sealed=1`,
   `launch_in_flight=0`, consumed/invalidated credential marker and empty claim
   hash). Here the consumed marker means credential destruction, not launch.
   Retain requested/floor history. Archive exactly once with the existing
   `managed_cancelled_before_start` outcome and exact reservation/request
   binding, while the separate receipt records actual isolated execution.
5. Delete only that verified direct reservation and any exact queue entry only
   if its complete binding and lack of another obligation were verified. No
   unrelated queue, worker reservation, execution, manifest or audit row is
   removed. Mark the exact registered exclusion `CLOSED` with the receipt's
   cleanup digest; preserve its immutable actors/Job binding. Do not create an
   exclusion row for a before-native or never-created branch.
6. Bump registry revision by the specified single transition, validate the
   entire expected postimage and its correspondence with the receipt, and
   commit all changes together. A receipt row by itself is incomplete evidence
   and must fail every active-slot/history validator. Rollback leaves the
   original reservation and exclusion protecting the experiment.

Canonical schema migration must revise the persistent experiment guards to
permit only this exact receipt-bound cancellation and exclusion-close
transition, while retaining all ordinary API guards. Admission metadata and
receipts remain immutable and undeletable. No deletion/transition becomes
legal merely because `cleanup_digest` is non-null or looks like a hash.
Readers that do not understand the revised schema must refuse it. Coordinate
source generation/consumer rollout before any schema activation.

After commit, positively settle that operation's original SQL connection and
daily guard, then perform exact postcommit readback before returning a settled
release result. Lost guard/connection cleanup keeps the operation pending;
it does not reverse an already committed cancellation or permit an unrelated
agent to remove its nonce. The existing POLICY fence prevents the next
experiment from entering until this original fence is settled. Close the
demand's final native self witness only through this retained operation after
its receipt/replay needs are settled; an uncertain close is retained, never
retried as an unrelated numeric handle.

## Replay, expiry and crash invariants

| Observation | Permitted next action |
| --- | --- |
| No writer attempt or a positively rolled-back attempt | Retain the same sealed demand, immutable completion and release operation. Retry its guarded publication after revalidating the exact binding; never reopen launch. |
| Commit may have succeeded; ACK is missing | Keep the same operation ID, receipt digest, preimage/CAS metadata and original POLICY/connection owners. Reconcile them, then compare every committed receipt, terminal row, archive, exclusion and allocation absence. No second cancellation, new claim or fresh native cleanup. |
| Exact committed tuple exists and cleanup has settled | Return the same result as replay without changing history, counters, timestamps or registry revision. Missing reservation alone is insufficient. |
| Receipt, archive, terminal row or exclusion is missing/changed/duplicated | Preserve originals and refuse success. Never repair by deleting evidence or inserting a guessed receipt. |
| Reservation expires before native cleanup | TTL may leave the daily execution in `UNCERTAIN_HOLD`; full demand and exclusions remain. Stop new work/control and restore with original scope custody. |
| Positive original completion after expiry | The new experiment-only transaction may cancel the exact expiry-held, otherwise unchanged unused daily claim directly from `UNCERTAIN_HOLD`. Validate the original allocation/hold provenance and full immutable binding. Do not reset it to `RESERVED`, renew the lease, or generalize this transition to arbitrary holds/ordinary cancellation. |
| Process dies before the first receipt commits | No historical row, dead PID, TTL or serialized completion can mint first-release authority. Keep demand held; recovery needs a separately specified genuine custody path. |
| Process dies after the whole receipt tuple commits | Historical validation can recognize already completed accounting. It cannot reconstruct a live completion or grant further native control. Any still-pending POLICY owner/fence remains separately unresolved. |

Seal the original demand even when release is refused. Reusing a released
experiment/request/command binding for new admission is forbidden. A legitimate
next experiment uses a new declaration and request after the prior obligation
has been positively resolved; old admission replay reports the old terminal
result rather than minting another allocation.

## History-preserving reuse and retirement inventory

Keep the single active-experiment limit. Replace the current all-row count in
`experiment_demand._schema`/`admission_blocker_locked` with bounded validation
that classifies each complete admission/receipt/cancellation tuple. Only a
fully verified terminal tuple ceases to occupy the experiment admission
position. A forged, partial or incompatible historical receipt blocks reuse;
an SQL `NOT EXISTS` anti-join alone is not its validator. Preserve all history
and fail on the history budget instead of deleting old rows to admit more work.

Revise exclusion schema guards/readers together. Retain every `CLOSED` row and
its matching cleanup receipt. `read_locked` must first validate its closed
history without requiring a now-deleted active reservation, then expose only
unresolved original actors and Jobs to the legacy writer. `assert_available_locked`
and the insert trigger count unresolved entries, retaining `MAX_SCOPES=1` and
the combined active Job bound. Old closed identities are not reopened by PID,
and old Job names/nonces are never reused. Increment the registry revision so
the actual daily legacy writer refreshes its exclusion inventory.

Provide a proposed bounded `verify_experiment_history_locked` reader shared by
admission reuse, exclusion history and daily retirement. It accepts a real
guarded connection and exact stored tuples, never a caller verdict. Validate
receipt schemas/digests, uniqueness, original admission/demand hash, truthful
daily cancellation, exact archive, invalidated claim, no direct/routed/queued
obligation, and matching closed exclusion or the defined no-exclusion variant.
It returns historical observations only, never `NativeScopeCompletion` or an
authority accepted by first-release publication.

Extend `daily_retirement_inventory` as one coordinated schema/reader change:

- Add exact receipt/exclusion layouts and trigger validation to the closed
  schema inventory. Include every experiment row in its aggregate byte/row
  budgets (`MAX_HISTORY`, `MAX_BYTES`) and digest; unknown schemas still refuse.
- Replace `experiment_retirement_unimplemented` only with the exact shared
  historical validator. Partition the matching daily `CANCELLED_BEFORE_START`
  experiment executions before the production Job/journal checks. These rows
  truthfully have no production Job or manifest; they use the experiment
  receipt branch, not a weakened production prelaunch receipt validator.
- Continue validating every other execution through existing production
  terminal/prelaunch receipts, including C2's unchanged `last_applied=None`
  requirement. A matching experiment receipt must never excuse a foreign
  execution or an unbound ordinary reservation.
- Preserve isolated terminal/intent/slot evidence in the durable completion
  receipt. The retirement inventory must not manufacture native proof from an
  external isolated file or reopen a closed Job to replace missing custody.
  Original first publication binds the captured isolated terminal evidence;
  all future reads verify that immutable historical record.
- Include the complete experiment history in capture and final SQL
  revalidation under the same original daily POLICY guard. Retain existing
  generation freeze, no-current-allocation/infrastructure, writer-obligation,
  production slot and recovery-journal requirements.

## Implementation order and required verification

Implement the original demand-to-preparation binding and positive completion
variants first; then the retained typed release operation and versioned schema;
then guarded atomic cancellation, exclusion/history reuse, and retirement
inventory together. Keep the existing unconditional release refusal until all
consumers understand the closed tuple. No interim trigger bypass is useful.

Portable verification must cover wrong/forged/reconstructed completion,
cross-demand/source/ledger binding, post-seal launch, before-native cancellation,
known pre-Create/Create FALSE cleanup, unknown creation/close, partial
preparation ownership, each isolated terminal variant, full reservation/floor
retention before commit, rollback at each statement, lost commit ACK and exact
replay, expiry to HOLD, persistent guard enforcement, malformed/duplicate
history, one-active-slot reuse, closed exclusion refresh and mixed ordinary
production/experiment retirement history. Prove no claim export or production
C2 relaxation and no native/isolated I/O inside the daily writer transaction.

Actual S1 provider verification still requires one real admitted daily demand,
the original authenticated native scope, observed restore/empty/owner close,
this exact committed receipt tuple and settled final fences, followed by a
legitimate next experiment's admission. A passing portable suite, live PID,
receipt-shaped JSON, native close flag or absent reservation does not establish
that end-to-end outcome.
