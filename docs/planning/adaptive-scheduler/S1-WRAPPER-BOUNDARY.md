# S1 root timing and wrapper readiness boundary

Contract before implementation, 2026-09-24. This is not an implementation or
native acceptance result. It follows the original scope/readiness contracts and
the child Create cutoff committed as `c2877da`. Production adaptive stays off.
The actual serial provider remains unavailable until its complete integration is
implemented and verified. This contract grants no activation or gate promotion.

## Scope and original authority

The original `DailyExperimentDemand` owns the actual daily allocation. The exact
`ExperimentNativeScope` owns its immutable command, guardian, isolated journal,
Job, original scope deadline and wrapper. The wrapper receives a launch request
only on the existing pipe authenticated to that original guardian. Its existing
`OnceLaunchState` permits at most one attempt. Neither a file, a deadline, a wire
generation row nor a readiness reply independently authorizes launch.

This change adds only (a) an inherited timing input for the pinned CPU fixture,
(b) a wrapper-local original readiness acquisition, and (c) original allocation
expiry restrictions at the root Create boundary. It does not add daily admission
to the wrapper/workload, a new POLICY binding, an authority callback, PID reopen,
or a retry path for an uncertain Create.

## Immutable command across queue waits

Before demand capture, select the scope UUID, Job nonce, isolated directory and
fixture/source pins. Capture the exact `ScopeCommand` once with two fixed new
root arguments: `--scope-id <UUID>` and `--scope-bound-stdin`. The normal fixed
arguments still contain the canonical root, source generation/digest, fixture
digest, Job name/nonce, directory, workers and declared maximum CPU seconds.

Do not put an absolute clock or a changing bootstrap digest in that command.
The same command, declaration hash and original demand survive queue waits.
Queue retries do not start or renew the native scope clock. Compare all command
source pins against the actual original admission binding before preparation;
a generation mismatch requires original cleanup, not command reconstruction.

`ExperimentNativeScope.prepare` still requires the exact command type and
`declaration.scope_sha256 == command.sha256`. Its existing original 120-second
deadline starts once at preparation and remains in the immutable scope tuple.

The root timing record deliberately contains NO `command_sha256`. The root has
no independent expected value for a hash of an argv containing that same hash.
It must not claim to verify that self-referential construction. Full command
verification remains in the original guardian/wrapper: pinned bootstrap digest,
exact `ScopeCommand`, fixture-byte verification, authenticated request command
hash, and the one-attempt state. Root input checks only the independently fixed
bindings below.

## Bounded inherited timing input

The wrapper creates one regular temporary file outside production data, retains
the original file owner before subsequent operations, writes the complete record
and rewinds it before Create. Its exact original handle replaces only the current
devnull stdin handle. stdout/stderr remain the existing devnull handles. Existing
explicit handle-list inheritance duplicates this handle for the child. No input
pathname, environment override, pipe, console or socket is accepted by the root.
No process writes the file after it is prepared. Do not reopen it by pathname.
An anonymous/delete-on-close regular temporary file is sufficient; no persistent
record becomes authority or a resume token.

Maximum record size is 4096 UTF-8 bytes, with exactly these keys:

```
schema_version: 1
kind: "S1ScopeTiming"
scope_id: exact UUID from immutable argv
job_nonce: exact nonce from immutable argv
source_generation: exact generation from immutable argv
source_digest: exact digest from immutable argv
fixture_sha256: exact digest from immutable argv
scope_deadline_monotonic_ns: original scope deadline, rounded down to ns
```

The deadline is a positive exact integer, not bool/float. All other fields have
exact types and existing UUID/nonce/digest formats. Reject unknown/missing keys,
duplicate JSON keys, invalid UTF-8, trailing data and nonfinite values. The root
must match every fixed binding against argv, including scope UUID, and continue
the existing source/bootstrap, self-hash and actual Job-membership checks. A
matching timing record alone cannot start CPU work.

Before reading stdin, inspect its existing descriptor with `fstat`: require a
regular file, positive size <=4096 and offset zero. Read only the bounded bytes
and EOF; compare the same descriptor's type, identity and size before/after.
Reject redirected/nonregular/oversized/truncated/changed input. Do not issue a
read-until-peer-closes operation. This avoids an open-ended pipe/console wait;
ordinary local file I/O can still fail or be delayed, and the original clock must
be checked after reading. It is not a claim that synchronous disk I/O has a hard
OS latency guarantee. The inherited stdin remains the process's original stdio
owner; do not introduce a guessed numeric-handle cleanup or an extra duplicate.

The wrapper retains its stream until its existing original cleanup closes it.
Failed/unknown file construction, write, seek or close keeps the actual partial
owner or acquisition marker; missing factory output does not prove absence.
Never set wrapper `local_closed` while this original stream is unresolved.

## One tree clock

Root startup records `started_ns` before argument parsing or timing/source reads.
After reading timing input and before native workload setup, compute once:

```
cpu_deadline_ns = min(started_ns + declared_seconds_ns,
                      scope_deadline_monotonic_ns - 4_000_000_000)
```

Require positive remaining CPU time; reject a scope bound more than 120 seconds
after root startup. The declared duration is still <=115 seconds. The two-second
self-stop prerequisite keeps its declared two seconds. Late startup is refusal
or less voluntary work time, never a new 115/120-second clock. The provider must
still prove complete fixed 30-second measurement windows; shorter work cannot
be reported as a passing window.

Every child receives the SAME `cpu_deadline_ns` through the existing leaf
`--deadline-monotonic-ns` argument. Leaves cannot use root stdin mode, spawn more
children or derive a new clock. The root may pass its fixed scope UUID along for
diagnostic consistency; the inherited deadline remains the work restriction.
The child Create cutoff from `c2877da` remains immediately after native argument
preparation and before Create entry. Root/leaf CPU loops and ready-wait loops use
that original deadline. Cooperative child observation may continue only until
`cpu_deadline_ns + 4 seconds`, which is no later than the original scope bound.

After the work/observation deadline, unresolved native custody remains retained
and idle. No kill, replacement child, fabricated exit record or daily release is
permitted. Such retention is cleanup, not an extension of CPU work permission.

## Full generation binding for the wrapper

Use the complete immutable row from `demand._original_generation_binding()` in
the pinned wrapper bootstrap: generation/state, source/config digests, source
manifest, source/ledger paths, original ledger identity, daily owner identity
and readiness endpoint, with the exact schema fields/types. The present
`demand._prepared[0]` three-field comparison is insufficient for this purpose.
The actual source-reader connection must positively close before bootstrap
publication. Never adopt a freshly read generation as the original pin.

Update the strict bootstrap schema together on both sides. Avoid duplicating the
potentially large source manifest: one exact original generation row can supply
the manifest used by bootstrap import attestation. Preserve the existing total
bootstrap byte bound and refusal on oversize; do not raise it opportunistically.

## Original allocation lease restriction

The guardian still proves actual daily allocation, original claim, full floor,
generation, fences and exclusion in `_coverage_locked` under its original POLICY
before persisting isolated launch intent. Capture an immutable launch-bound
record from that exact validated allocation before returning authorization:
allocation identity/binding, its positive finite `expires_at`, and an absolute
monotonic cutoff. This record belongs to the same scope/launcher/request; it is
not independently constructible launch authority.

Use the earlier of any already-pinned original allocation expiry and the current
validated expiry. This protocol never renews the allocation or upgrades an older
cutoff because a heartbeat moved expiry forward. Pair a monotonic sample taken
before a wall-clock sample and derive conservatively:

```
remaining = pinned_expires_at - wall_sample
lease_deadline_ns = min(original_scope_deadline_ns,
                       monotonic_sample_ns + floor(remaining * 1e9))
```

Require positive finite remaining time. Capture once for the original launch
attempt; SQL close, journal work, lock exit, IPC and wrapper setup consume it.
Never recompute it on receipt, observation, replay or cleanup. A backwards wall
clock cannot extend the fixed monotonic cutoff; a forward wall jump is caught by
the original wall-expiry check.

The authenticated launch request carries only those frozen timing restrictions
and the exact allocation identifier/binding. Bind their canonical value to the
original request ID and retain it in the original launcher/wrapper state. Do not
accept changed values on repeated delivery. Non-launch requests carry no new
bounds and cannot refresh them. The wrapper must compare scope identity and all
available bootstrap bindings, require the cutoff no later than the original
scope deadline, and reject expired/malformed input before Create.

The exact `launch_bounds` keys are `reservation_id`, `binding_sha256`,
`expires_at`, and `lease_deadline_monotonic_ns`. Preserve the earlier validated
expiry before `_coverage_locked` can replace its existing restriction field;
freeze the launch record inside the same allocation transaction. Bootstrap v2
contains one `generation` row plus original `reservation_id`/`binding_sha256`;
do not repeat the source manifest separately. Launch request v2 requires the
bounds; non-launch requests retain their v1 shape. Replay compares the canonical
bounds as well as original request ID and command hash, before returning no-op.

These serialized values only make an already authorized operation expire. They
do not prove allocation ownership or replace the guardian's actual transaction.
The wrapper cannot issue an admission, heartbeat, acquire another reservation,
or infer capacity from them. The actual floor remains held through native close
and original receipt-verified release even when these restrictions expire.

## Wrapper-local readiness and dual deadline entry

Only after receiving the launch request over the original authenticated guardian
pipe does the wrapper attempt launch. Mark its existing one-attempt state before
readiness/native/file acquisitions; clean refusal does not create a second
launch attempt. Prepare source verification, timing stream, native Job handle,
mutex and stdio owners, then acquire one original wrapper-local
`daily_generation.readiness_scope(actual_ledger_path)` outside the Job mutex.

The wrapper's fresh readiness acquisition is independent of the parent's
already-used readiness scope. It must match the complete original generation
row in the pinned bootstrap. It obtains its own actual authenticated daily peer
and original <=1-second `NativeDeadline`; no parent deadline/peer is serialized,
reconstructed, replaced or renewed. It provides readiness, not daily capacity.
The original guardian request/one-attempt state remains separately required.

Keep that lexical scope alive across the Job mutex and Create. Under the mutex,
use `revalidate_scoped_readiness(path, expected_generation=original_pin)` only;
no new readiness RPC or SQL acquisition under the Job lock. Require the original
wrapper-local authority and unchanged returned deadline, exact empty Job, source
pins and original time restrictions before entering the launcher.

Extend `native_launcher.launch_in_job` with an optional exact
`readiness_deadline` in addition to its existing `native_deadline` (the original
five-second exchange deadline). Validate both exact types before any effects.
At the existing final native cutpoint, after stdio/attribute/command/capture
preparation and before marking Create entered, require BOTH original deadlines,
the original scope bound, the frozen lease monotonic cutoff and original wall
expiry. Optional scalar lease restrictions must be exact finite/bounded values
validated before effects, with no callback. No new deadline is constructed from
remaining time inside the launcher. Ordinary callers with omitted restrictions
retain their existing behavior. Restore/disable and positive cleanup remain
independent of these creation restrictions.

Use the optional paired `lease_deadline_monotonic_ns` (positive exact int) and
`lease_expires_at` (positive finite int/float, not bool) parameters for the frozen
lease restriction. Reject supplying just one before effects. No callback or
serialized `NativeDeadline` is introduced.

All freshness/source/setup work consumes the original wrapper authority window.
A timeout before kernel entry retains the original `CreatedProcess` with known
not-attempted output custody. Create FALSE, partial output and unknown Create
keep their existing distinct meanings. A timeout after a possible Create can
only reconcile the same original process, never repeat Create.

## Readiness cleanup joins original wrapper custody

The wrapper must retain the actual readiness scope and complete bounded cleanup
error graph before acquisition/exit. Unknown reader/peer/duplicate/close keeps
the original wrapper alive and prevents `_drain` from claiming `local_closed`.
Its current `_close_unknown`/`_acquisition_pending` checks alone are insufficient
for new `_daily_readiness_*` owners. Preserve every original owner attachment;
do not replace it with a boolean or safe-text diagnostic.

A clean readiness timeout/rejection whose original acquisitions all positively
settled may drain a never-created root. Readiness close uncertainty after a
successful Create must still preserve the root offer/transfer and original
process; failure reporting must not hide native custody. The guardian retains
daily floor and uses existing original observe/seal/drain reconciliation.
Unknown cleanup is never retried through a new readiness acquisition. No result
frame alone proves wrapper transport or final native closure.

Retain handled `native_launcher` errors and its exact `CreatedProcess` immediately,
but raise that error only after readiness has positively exited. Otherwise native
error notes can poison the readiness scope before it closes an unrelated peer.
Actual readiness or Job-lock cleanup failures still propagate normally and keep
their full original graph; never defer them as ordinary launch diagnostics.

## Required focused source verification

- Command bytes/hash and original demand unchanged across a long queue wait;
  scope clock begins only at preparation; changed source pins refuse.
- Root rejects nonregular stdin before reading, oversized/duplicate/trailing or
  changed records, each mismatched fixed binding, and expired timing. It makes
  no unsupported command-hash assertion.
- Timing stream is prepared/rewound before Create and retained on each partial
  open/write/seek/close outcome. Child inherits only explicit stdio handles.
- Root/children share the same original CPU cutoff; bootstrap delay consumes it;
  scope-minus-grace is enforced; the child pre-Create cutoff remains tested.
- Wrapper authenticates original guardian before readiness; RPC occurs before
  Job lock; wrong full generation/ledger/endpoint/config/source refuses.
- Consuming either original deadline or lease/scope bound during actual launcher
  setup prevents kernel Create without marking creation entered. Wall-clock
  backward/forward movement cannot extend the frozen cutoff.
- Unknown readiness close before/after Create retains original scope/peer/root
  custody and prevents local-closed acknowledgement; clean refusal can drain.
- Lost launch/result ACK allows only original observe/seal/drain; duplicate or
  changed request cannot renew any bound or launch again. Daily release waits
  for existing original completion and final receipt settlement.

Portable tests establish these source invariants only. Actual serial S1 native
execution, canonical aggregate-provider bootstrap and all gate evidence remain
separate, unverified work.

