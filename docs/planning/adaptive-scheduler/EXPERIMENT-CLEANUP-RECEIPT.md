# Original experiment cleanup receipt and daily demand release

Status: implemented original release contract for item 5 of
[S1-DAILY-BRIDGE-CONTRACT.md](S1-DAILY-BRIDGE-CONTRACT.md). The original proposal
was based on source following `ebd936c`; its source-boundary table below is
historical context. Daily adaptive remains off. No native capability gate or
production activation is claimed.

Implementation checkpoint (2026-09-24): `prepare_release` retains the exact
completion, original generation and POLICY binding. `Coordinator.release_experiment`
now publishes the immutable receipt, unused daily cancellation, archive, exact
reservation/queue removal, CLOSED exclusion and one registry revision in one
transaction. It reports success only after positive SQL/native POLICY cleanup,
full committed-history readback and original final self-witness close. Completed
replay performs bounded reads only. Private per-guard positive-exit/no-entry and
nonce-clear facts preserve the original attempt; they confer no new authority.
Full-row temporary receipt/archive guards supplement persistent exact mutation
guards. A correct receipt ID/hash cannot authorize a different payload. Every
write revalidates the actual connection, frozen preimage and original guard;
SQLite statement caching cannot bypass those checks.

The stored IPC key must match the original admission snapshot with a
constant-time comparison before publication. A never-COMMIT-attempted candidate
may be discarded only after a positively confirmed rollback, original SQL close,
native exit/no-entry, nonce cleanup and complete-history readback proving that
the original demand is still active without a receipt. The next writer then
freezes a newly validated preimage under the same original operation/completion.
This permits ordinary expiry to HOLD and registry revision changes after a
known rollback. A lost COMMIT acknowledgement is never rebased; its original
candidate remains the sole reconciliation target.

Unknown native/SQL/self close retains the original owner and refuses reopening.
A documented final CloseHandle FALSE may retry only that same original owner
after full readback; positive close followed by interrupted local bookkeeping
resumes without another native call. Initial admission uncertainty before a
completion can be minted now has a separate original-only settlement route,
described below. It clears the original pending guard after positive cleanup;
it grants neither completion nor capacity-release authority.

The separate `experiment_history` module implements the closed, bounded data
validator. It validates the immutable admission metadata, exact terminal managed
row, unique archive, absent live obligations and matching closed exclusion as one
tuple. The validator itself does not open a connection, install its exported
schema, publish a receipt, mint a native completion or release capacity. The
admission/exclusion/retirement consumers are integrated: only validated complete
history can free a serial experiment position. Retirement shares the original
SQL-row inventory and 16 MiB budget with ordinary production history.
Verification: nine related modules, 165 tests passed in 21.627 seconds, zero
failures/errors/skips, including 23 history cases. These isolated synthetic
records test data validation, not native cleanup. Consumer verification passed
204 tests in 44.941 seconds. Original release/fault verification passed 58 tests
in 20.604 seconds; original scope/release/consumer verification passed 124 tests
in 33.557 seconds. All had zero failures/errors/skips. The five completion
variants now exercise original factories and SQLite transactions; native I/O,
source/readiness attestation and transport remain explicit synthetic fixtures.
These overlapping batches must not be added as a distinct-test total. No fresh
real native admission or S1 serial-provider acceptance is established by them.
After independent review and the rollback/key fixes above, the combined final
17-module regression passed **322 tests in 85.971 seconds**, zero failures,
errors or skips. Its two new release test files contain 33 test methods. The
planning README records the equivalent command and the private log path.

The required result is one truthful daily cancellation after the original
isolated experiment has positively completed native cleanup. The daily claim
never launched anything: its reservation covered a separately executed test.
The daily execution therefore ends as `CANCELLED_BEFORE_START`, while the
separate experiment receipt preserves whether the isolated root ran, never
launched, or no wrapper was created. Neither outcome is production `FINISHED`.

## Source boundaries at the original proposal

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

The following minimal API is implemented. These are exact concrete types with
private construction and original-object retention, not protocols accepting
user callbacks or duck-typed `complete=True` objects:

```python
# Before ExperimentNativeScope.prepare enters any preparation side effect:
scope = ExperimentNativeScope.prepare(demand, command, ...)
# Its original factory internally binds the new scope to demand first.

completion = scope.close_native()      # existing NativeScopeCompletion or None
operation = demand.prepare_release(completion)  # retained original operation
result = coordinator.release_experiment(operation)  # exact daily route

# Alternative, only when native preparation was never entered:
completion = demand.seal_without_native()  # original BeforeNativeCompletion
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
the current `NativeScopeCompletion` cannot be assumed to cover them. A positive
early-preparation path has the distinct `PREPARATION_CLOSED` disposition: no
wrapper was created and no successful Job escaped preparation, and every
attempted acquisition is accounted by its retained original owner and positive
close or its original never-entered slot. A missing constructor return is not
positive accounting. Until that path positively settles, the reservation
remains held; it never becomes `BEFORE_NATIVE` retroactively.

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

The bounded, append-only table is
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
| Native disposition | Closed enum: `BEFORE_NATIVE`, `PREPARATION_CLOSED`, `WRAPPER_NOT_CREATED`, `NEVER_LAUNCHED` or `FINISHED` **for the isolated experiment only**. Exact original completion digest; nullable scope fields are allowed only by the defined variant. `PREPARATION_CLOSED` preserves the exact retained attempted-owner accounting and never invents a wrapper or successful Job. |
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

The dedicated retained `ExperimentReleaseOperation` lives in
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

## Original generation binding and release-only SQL amendment

This amendment specified the release slice now implemented above. Its authority
comes from the exact original operation; preparation/readiness tests alone never
establish receipt publication or capacity release.

During the original authenticated admission, retain the complete validated
daily generation row on the original demand, before admission can publish.
The current `_prepared` tuple contains only generation/source/config digests
and is insufficient for this full binding. Pin every immutable generation
field, including source manifest/root, ledger path/file identity, original
generation-owner identity and readiness endpoint instance. Include that pin
in the immutable completion and release-operation binding. The only permitted
later row difference is the same generation's `ACTIVE` to `DRAINING` state
transition. Never fill missing original fields from the row first observed
during cleanup; an older demand lacking this original pin must refuse release.

The exact original `ExperimentReleaseOperation` supplies cleanup authority
through its retained demand and concrete original completion. Add only a
dedicated lexical operation seam to `daily_generation` and the existing
POLICY/connection hooks: require that exact registered operation, ledger,
thread, sealed binding and phase. It must not acquire or renew daily readiness,
depend on the admission lease still being live, adopt a generation owner, or
construct a `DailyReadinessAuthority`. Revalidate source/import provenance,
config, generation fields and file identity on the actual consumer connection
and after its `BEGIN`. No side connection, live-status lookup or new peer can
replace those checks. A changed/unavailable source or ledger still refuses.

The operation owns these distinct, narrowly authorized connection phases:

| Phase | Permitted operation and original custody |
| --- | --- |
| Read and reconcile | Bounded reads of the exact original bindings and full pre/postimage; no capacity UDF or mutation authority. |
| Publish POLICY nonce | Require an already-initialized, unchanged original POLICY binding. Publish only this operation's candidate nonce against a null preimage, retaining the original attempt before SQL. No binding initialization or replacement is allowed. |
| Hold and publish receipt | Reuse the existing native POLICY acquire/revalidate/release order. Under the same guard, permit only the reviewed receipt, exact cancellation/archive, exact reservation/queue deletion, exclusion close and one registry revision transition. |
| Clear original nonce | Only after positive original native release, clear exactly this operation's guard nonce to null. Preserve current timeout/unknown-release rules and the original guard if SQL acknowledgement or close is uncertain. |
| Postcommit readback | After positive original SQL and guard cleanup, verify the entire exact committed tuple through retained operation custody before reporting release complete. |

The existing `readiness_nonce_cleanup` and `_nonce_only` provide exact nonce
fencing, not release authority: they only clear an
already-owned nonce. The original local install and retirement
`authorize_nonce_cleanup` paths remain separate. `RetainedPolicyOperation`
and the original managed-submission reconciliation provide existing custody
patterns; their reads and holds also need the same release lexical seam, so
they must not silently enter a fresh readiness RPC during cleanup.

The current `daily_generation._install_triggers` requires `ACTIVE` plus
`sentinel_daily_generation()` for every capacity INSERT/UPDATE/DELETE.
Consequently a connection hook alone cannot implement this contract. Revise
the canonical persistent guards together with the receipt schema so that only
the exact original receipt-bound reservation/queue DELETE can take the
release route in `ACTIVE` or `DRAINING`. Cleanup must never install a fake
`sentinel_daily_generation`, return a generation string as general capacity
authority, or exempt arbitrary DELETE statements. Other writes retain their
existing daily authority requirement. Preserve and validate the retirement
fence, experiment immutability guards, exclusion guards and full historical
tuple; readers unable to validate the revised canonical schema must refuse it.

Focused verification must include an expired/unavailable readiness service,
the same original row in both states, a changed endpoint/owner/source/file
binding, missing original admission pin, attempted new POLICY binding,
unrelated row deletion, wrong phase or retained connection after lexical exit,
and lost ACK/unknown cleanup. No new native experiment or runtime activation
is authorized by this amendment.

### Canonical DELETE guards and nonce custody

SQLite resolves trigger function names before executing their conditions, so a
cleanup connection cannot merely skip a branch that mentions the unavailable
capacity UDF. The canonical reservation/queue DELETE guards now call the fixed
`sentinel_daily_delete_authority(table, exact_key)` instead. Normal consumers
implement it by the existing full current-generation ACTIVE validation. The
unactivated installer and release read/nonce phases receive no delete authority.
The receipt publication phase binds that function to the exact
original operation, same connection/guard and receipt-bound OLD row; no general
DELETE exception is permitted. The other ten capacity triggers are unchanged.
All twelve canonical definitions are checked together; missing, altered, extra
or dangling guards refuse without repair. This source change does not migrate
an installed generation or allow an older generation's guard set to be adopted.

The original nonce candidate is retained before the first SQL attempt. Unknown
native entry/close and SQL cleanup retain their original owner graph, including
bounded nested cause/context, and prevent reopening. A later timeout cannot
overwrite an earlier failed nonce-clear connection owner. A lost COMMIT ACK
with positive SQL cleanup may reconcile only that original candidate; it never
reads a nonce from the ledger and turns it into new ownership.

The durable envelope distinguishes `cleanup_digest` (domain-separated original
completion/demand/operation binding) from `receipt_sha256` (the entire canonical
pre/postimage record). CLOSED exclusion rows reference the former, avoiding a
digest cycle without omitting the exclusion postimage from the latter. A full
original source manifest may require a bounded 2 MiB receipt_json cell; the
retirement reader allows that exact canonical column while preserving
its 64 KiB default cell bound and shared 16 MiB aggregate inventory limit.

## Original admission settlement before completion (implemented source)

An initial admission may commit successfully and then lose its COMMIT or nonce
clear acknowledgement. `seal_without_native()` seals future work before checking
submission cleanup. Re-admitting that sealed demand is correctly refused, but
there must be a distinct way to settle its retained original admission guard.
No completion can be required as input: minting that completion is the operation
currently blocked by the unfinished admission guard.

`Coordinator.settle_experiment_admission(demand)` accepts only the exact original
`DailyExperimentDemand`. Retain a separate concrete settlement operation before
its first SQL acquisition. Seal further admission/native preparation without
resetting any existing seal. It owns only bounded reads and exact original nonce
clear; it cannot prepare/acquire a new POLICY guard, take capacity readiness,
change a capacity/queue/exclusion row, release a reservation, close the original
self witness, or mint a completion. Its result describes submission cleanup and
the observed original admission state, never launch or capacity authorization.

Bind the actual demand, inner admission, snapshot, original process witness,
generation pin, ledger/file identity, submission POLICY/store, returned guard,
nonce, original transaction and prior failure. A replacement guard/transaction,
unreturned prepare result, exported claim, native preparation, unresolved SQL
close, or uncertain native cleanup refuses. The original guard's positive
native-exit/no-entry facts are necessary; a missing nonce alone is insufficient.
Existing native/readiness/connection owners on the original error remain
retained and cannot be discarded by creating this settlement operation.

Use the same closed cleanup connection boundary as release, but permit only
READ and CLEAR. On the real consumer connection and after BEGIN, validate the
full original generation (ACTIVE or DRAINING), source/import/config, file
identity and original POLICY binding. Never reconstruct authority from a new
generation, current ledger nonce or serialized completion. The only write is
that returned guard's exact nonce-to-null transition after positive native
cleanup. Lost clear acknowledgement can be reconciled by a positively closed
original read; unknown SQL/native close quarantines the original owner and
forbids reopening. No general capacity UDF or native wait is needed.

Read the original request/metadata and bounded full experiment history before
and after cleanup. Verify an admitted unused row against the original private
key/claim and metadata, while preserving reservation/floors/expiry and immutable
history. An absent row after an uncertain COMMIT is merely observed absence,
not proof that submission never happened. Only an exact original positively
rolled-back, never-COMMIT-attempted first transaction permits a rejected-state
classification. Queued or absent states remain separate from admitted cleanup;
settling a guard does not cancel their request or invent an admitted receipt.

Only after positive original cleanup and final readback clear the inner pending
guard/error bookkeeping. Keep the operation and original error graph retained.
The caller may then ask the existing `seal_without_native()` to prove an
actually admitted unused claim and use the already implemented release route.
Repeat settlement must not reacquire/re-publish a nonce, renew capacity, or
replace any original owner. This amendment adds no native acceptance evidence
and does not activate the daily source/configuration.

Implementation boundary: shared cleanup access accepts only the two concrete
retained operation types. Settlement can enter READ/CLEAR only; release retains
its separate completion-bound publication authority. A cycle-safe 32-node error
graph preserves nested original clear failures. A positive SQL close followed
by a lost clear acknowledgement can retire its original readiness authority;
unknown close or native cleanup retains that authority and forbids reacquisition.
Partial local bookkeeping after confirmed cleanup may resume on the same owner,
without another nonce write, fresh guard or native call.

The two new test files contain 30 cases using actual isolated SQLite flows and
explicit synthetic identity/native/transport fixtures. The focused six-module
run passed 92 tests in 29.889 seconds with zero failures/errors/skips. The first
84-test run had one fixture error: the original quarantined demand correctly
refused before creating a settlement operation. The repaired assertion checks
the retained original failed connection and repeated refusal without SQL.
These are source/custody tests, not native acceptance. Queued/rejected final
context cleanup remains separate work; settlement never cancels those rows.
The final 25-module consumer regression passed 607 tests in 88.498 seconds,
zero failures/errors/skips (88.753 seconds including runner overhead). It covers
readiness, generation/retirement, POLICY, guardian, native identity smoke,
original experiment scope/release and managed admission. The planning README
records the exact equivalent command. Tests rely on the protected dirty
baseline; this is neither a clean-clone full-suite result nor native control
acceptance. No daily configuration, Scheduled Task or global startup changed.
