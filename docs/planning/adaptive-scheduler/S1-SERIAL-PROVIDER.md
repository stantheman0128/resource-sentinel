# Serial S1 provider and original case custody

Contract, 2026-09-24. This is the concrete integration contract for goal items
5/6, following `S1-WRAPPER-BOUNDARY.md` and `EXPERIMENT-CLEANUP-RECEIPT.md`.
The planning README remains the progress authority. This document grants no
production activation and establishes no native capability result.

## One real daily demand per case

`tests/windows/adaptive_s1_provider.py` owns a concrete serial provider and one
original case at a time. Retain the case before the first resource-acquiring
factory. Its UUID, scope UUID, nonce, isolated directory, canonical source pins,
command and declaration are fixed before capture/admission. Keep original
exceptions and partial owners; a missing factory return is not known absence.

Build the exact `ScopeCommand` for base Python `-I` and the reviewed
`adaptive_scope_cpu_worker.py`, including canonical root, source generation,
source digest, fixture hash, directory, worker count, declared duration, Job
name, nonce, scope UUID and `--scope-bound-stdin`. No changing absolute clock
belongs in the command hash. The exact `ExperimentDeclaration` uses this command
hash and actual S1 resource demand, not a lower estimate to gain admission.

Capture `DailyExperimentDemand` once; construct the actual daily `Coordinator`
for that demand's original ledger. Do not supply measurements, config, injected
capacity, a replacement ledger, or the old `S1Runtime` authority. Repeated queued
attempts use the same original demand and command. A capacity wait remains pending;
no native scope clock/Job begins while queued. Public admission settlement seals
new work and must never be used as an ordinary admission poll.

After admission, compare the original admitted generation with the command's
source pins. Prepare `ExperimentNativeScope` once with the original scope UUID
and nonce. Retain the registered partial scope on error. An uncertain preparation
or launch cannot be retried by constructing another scope/demand. Use the scope's
existing launch, coverage, control, probe, restore and close APIs. The wrapper
does not acquire a second capacity claim.

## Cleanup and recovery are part of the provider

No next case starts until the previous one positively releases or abandons its
original daily demand. A state label, copied JSON, elapsed TTL, root exit, empty
Job or closed native handle cannot release capacity.

- A clean successfully captured demand before any submission preparation uses
  its original `close_unsubmitted()`; that method verifies no submission or
  pending guard before closing its original process handle. Failed/partial
  capture or unknown preparation remains held; do not fabricate a guard.
- After actual submission preparation, never submitted, queued or positively rejected: original
  `Coordinator.abandon_experiment(demand)` must positively finish its original
  checks and self-close. Only its returned terminal disposition ends custody.
- Interrupted admission: settle the same original admission guard with
  `Coordinator.settle_experiment_admission(demand)`. This permanently seals new
  work. Its observation then selects abandon or unused-admitted cleanup; it is
  not itself completion. Missing/ambiguous states remain held.
- Admitted before any native preparation: obtain the original
  `seal_without_native()` capability, retain its `prepare_release()` operation,
  then use `Coordinator.release_experiment()`.
- Native preparation entered: retain that original scope, restore through it,
  request voluntary stop only using that case's fixed `stop` marker, and tick
  `close_native()`. A `None` result remains pending. Only its exact original
  completion may prepare the original daily release operation.
- Lost release acknowledgement retries that same retained operation. Known
  close failure retries only the original supported owner. Unknown acquisition,
  native release or SQL-close outcomes remain held without a replacement.

`recover_once()` performs only the above cleanup. It never launches, makes a
new case, repeats a measurement, reconstructs custody, or grants capacity.
Completed observations may be saved only after positive original cleanup.
Errors during logging or repeated interrupts must not discard custody. The
eventual console entry retains `NativeRunUnsettled` and runs cleanup ticks in
the same process; successful cleanup after a failed test reports failure.

### Original successful-admission result handoff

An interruption after actual admission returns but before the provider records
the result must enter cleanup-only settlement of that original attempt. Publish
the unclassified-attempt marker before the call and clear it only after exact
result classification. Never infer a queue or allocation from local defaults.

Successful admission may already have cleared its pending guard. Settlement may
then use only the exact retained `demand._submission_original` tuple (policy,
store, original PolicyGuard, binding and nonce), with the same positively closed
original SQL transaction. Retain the tuple by identity and revalidate all pins;
require positive original nonce-clear and native-cleanup facts, a still-None
pending guard and no policy cleanup error. Missing, replaced or unknown evidence
remains HOLD. Never reconstruct or republish a guard, perform another admission,
clear a new nonce, or adopt authority from a later database row. Settlement's
existing original read-only classification still grants no release or launch.

Test successful admitted and queued attempts whose outer reply is lost, plus
an interrupt during provider classification. Recovery must settle the same
attempt and then positively release or abandon through its existing original
operation; uncertain cleanup cannot start the next case.

## Measurement and evidence integration

Adapt S1 in `adaptive_capability_runner.py` explicitly to the new exact provider;
do not cast it to the old owner API. Keep unrelated S2/P6's no-argument admission
placeholder refusing until their own actual integration is complete.

Preserve three prerequisites (two-second self-stop, empty cap/reopened restore,
foreign-parent rejection), then ten distinct rounds. Each round has full 30 s
uncapped, capped and restored windows, rate 2500, workload maximum 115 s and
original scope maximum 120 s. Setup consumes the original clock. Do not renew
the clock, shorten windows, retry selective rounds or relax reducer thresholds.

Ready files are bounded observations, matched to original root identity, exact
Job membership, nonce/scope/source/fixture pins and one common actual work cutoff.
Every window must end before that cutoff and the original scope deadline. Use
raw Job CPU 100 ns and monotonic ns measurements. Observe actual scope control
during a capped window and reject one that restored early. Outside cap, continue
actual coverage/native-state checks. Do not hold locks during waits or IPC.

Keep the principal Job open while using a genuine original CONTROL probe to read
the cap and restore. Verify both handles disabled and close the probe positively.
Infrastructure exclusion covers original guardian and wrapper witnesses. Job
security values must come from a typed same-handle query, not constructor success
constants. Cleanup fields must derive from original completion/journal and the
verified daily release, not old isolated row counts or hardcoded zeroes.

## Bootstrap and source gate

The console entry will be `tests/windows/run_adaptive_s1.py`, standard-library
only before attestation, invoked with `C:\Python313\python.exe -I`. It must load
production only from the canonical daily source and attest the completed imports
against that generation. It must separately pin and execute the reviewed finite
fixture closure, including initializers, runner, provider, scope launch, wrapper,
workload and entry. Exact `tests.windows.adaptive_scope_launch` identity is
required by the scope API. No general worktree import path or stale pyc fallback.

Mixed canonical runtime/worktree fixture build observations need a concrete
producer/consumer binding before this entry can publish native evidence. The
current `CurrentBuildSource` hashes tests under its own production root and
cannot represent different executed fixtures. Do not rewrite `_ROOT`, accept
reported CLI hashes, or copy tests into the production installer to bypass this.
This provenance bridge and security observation have their own source/tests;
the custody provider can be implemented and verified before the console unlock.

## Verification and promotion

Test actual original queue/admit/settlement/abandon/release dispatch, partial
factory custody, lost ACK, no-next-case while held, original-only cleanup,
generation mismatch, exact type/source refusals and zero artifact publication
while unsettled. Isolated SQLite and explicit native fixtures test source
behavior; they do not pass S1 or any later native gate.

Native S1 still requires separately authorized canonical source activation,
fresh generation and external console execution. Commit/push is not activation.
No daily config/Scheduled Task/global startup changes, user-process control,
new exemption, shorter lifetime policy or adaptive-on setting is authorized.
