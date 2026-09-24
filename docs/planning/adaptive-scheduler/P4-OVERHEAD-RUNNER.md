# P4 native overhead measurement engine

This is the item 6 producer-side implementation for formal plan sections 11.2
and 12.1/S4. It is not a native gate result, daily activation, or permission to
enable adaptive control. No measurement has been executed as part of writing
this implementation. Production defaults stay off.

## Entry point and current prerequisite

`tests.windows.adaptive_overhead_runner.produce_p4(coverage,
evidence_directory, context, profile)` returns the exact raw P4 `data` object
accepted by `NativeEvidenceRun.publish_gate("P4", data)`. The profile must be
shadow with a 1-second sample interval. There is no reduced-duration CLI,
environment override, synthetic gate switch, or imported measurement file.

The concrete native measurement engine is implemented. The authenticated
aggregate daily fixture-owner bridge is a separate, **currently missing**
integration. The existing `S1Runtime` owns one serial managed execution; it
does not expose the required cross-process guardian/wrapper cohort. The runner
therefore refuses with `p4_authenticated_daily_cohort_unavailable` before native
initialization when `coverage.open_overhead_session` is absent. A generic
callback or a JSON boolean must not be connected as a replacement provider.

`DailyGenerationOwner.assert_ready()` proves the retained daily source/cohort
handoff. It does not independently provide fixture launch/adoption or authorize
these scopes. Completing that handoff cannot remove this producer prerequisite.
Admission must always use the real daily ledger, not the isolated evidence DB.

## Required aggregate bridge contract

The original coverage owner must implement
`open_overhead_session(jobs, directory, profile, query_only_stress)`.
It retains the pending creation attempt before the first native operation and
returns one in-process session with the following original custody:

| Session member | Required meaning |
| --- | --- |
| `helper` | Retained `VerifiedProcess` for the current external-console runner. It executes the actual helper loop and all probe work, all of which is charged to monitoring CPU. |
| `helper_host` | The initialized original `OperationalHelperHost` in shadow mode, in that same process, with its actual registry, QUERY handles, parent witness and operator endpoint. A PID, `ShadowHelper` core, approval flag or reconstructed object is insufficient. |
| `helper_telemetry_sink` | Original running `ResidentTelemetry` installed on the actual helper. Its canonical shared `adaptive-telemetry` directory is exactly `log_directory`; all resident log files and metadata count. The original worker remains in the helper process and its CPU/private memory is charged. |
| `guardian` | Retained exact witness for a real isolated guardian host. A sleeping fixture must not be labeled guardian. |
| `wrappers` | Exactly `jobs` original witnesses for real waiting wrapper hosts, all retained and continuously covered. |
| `daily_monitor` | Original `tests.windows.adaptive_daily_monitor.DailyMonitorWitness`, captured from the original admitted S2/P4 `DailyExperimentDemand` before fixture creation. Its authenticated retained cost witness must be used for both accounting keeper and daily activation/readiness roles. It grants no admission, launch, control or retirement authority. |
| `monitor_processes` | Tuple of `(role, original VerifiedProcess)` pairs covering exactly one helper, guardian, supervisor, accounting keeper and daily activation/readiness owner, plus every waiting wrapper. Keeper and daily activation must be the exact original witness returned by `daily_monitor.assert_original()`. Supervisor must be the actual `helper_host.parent_process`; it may be a separate process. If it shares the keeper's exact identity, it must use that same witness object. Preserve all roles and charge each exact identity once. No caller-only demand witness or arbitrary same-logon process may be relabeled as a keeper. |
| `jobs` | Exactly `jobs` pairs of canonical execution ID and retained native `QUERY` Job handle. Fixture owners retain the corresponding original launch/cleanup custody. |
| `scope_nonce`, `context`, `profile_revision` | Exact native scope, current host/logon/topology context, and profile binding. |
| `database`, `log_directory` | Isolated runtime database and bounded runtime logs, distinct from producer raw evidence. The daily admission DB is never supplied here. |
| `assert_daily_coverage()` | Bounded actual daily allocation/adoption check for every fixture and infrastructure member; returns `None` on success. Unknown, stale or lost coverage raises and preserves original owners. |
| `read_guardian_set_audit()` | Authenticated read of the guardian's actual native Set boundary instrumentation, installed before the experiment. Returns typed `NativeSetObservation` bound to the exact peer and scope with advancing sequence, original install tick and cumulative counters. |
| `read_resident_telemetry()` | Authenticated reads of original guardian and supervisor `NativeTelemetryProbe` objects, returning exactly those two typed `NativeTelemetryObservation` values. Validate the original peer/scope before returning; neither the value's type nor a callback is authentication. Helper observations are read directly from its retained original probe. |
| `enter_idle()` / `enter_stress()` | Cooperative commands to the owned fixtures. Preserve the same helper, guardian, waiting wrappers and Jobs. Stress churns children within those Jobs; do not manufacture lifecycle rows, stop user work or clear historical state. |
| `prepare_wrapper_trial(kind, iteration)` | Actual admission preparation completed outside the latency bracket; returns an original once-only launch attempt, already retained by this session. |
| `retire()` | Provider-owned cooperative stop, actual Job empty/disabled verification, lifecycle/archive settlement and original-handle cleanup before release of daily capacity. |
| `custody_pending` | Observable pending state after retirement, not an authorization to release resources. The bridge itself performs the exact proofs. |

Each wrapper trial exposes `launch_once()`,
`wait_ready(assert_covered=...)`, `retire()`, and `custody_pending`. Ready must be
an authenticated actual wrapper-ready observation, not merely a live PID.
`wait_ready` calls the supplied continuous check at most one second apart and
retains unknown creation/readiness outcomes. That callback also services the
original helper when its actual pending deadline is due; the helper remains
active during latency trials. Its real polling/reporting work is not subtracted
from readiness latency. Ordinary pacing completes outside the latency bracket.
Cold means a newly created wrapper
host; warm means the defined already initialized host/cache path. Both modes
must invoke the actual admission-only wrapper implementation. Their source and
launch topology belong in the same native evidence run as the artifact.

An exception during bridge creation leaves custody in the original coverage
owner. Once a session exists, measurement or cleanup failure raises
`OverheadUnsettled` with that exact coverage/session and local query owners.
An interrupt is re-raised with the same retained owner attached. The external
orchestrator must remain resident and recover those originals; it must not
serialize a receipt, reconstruct owners from PIDs or exit with live obligations.

## Authenticated daily cost witness source slice

`DailyMonitorWitness.capture(demand)` accepts only the original admitted,
settled, unused `DailyExperimentDemand` for S2 or P4, before native preparation
or sealing. It verifies the pinned canonical source and authenticates that
generation's exact readiness endpoint with the existing bounded native client.
The full generation/source/config/ledger binding is sent through the actual
readiness protocol. Capture runs outside POLICY/Job locks. It duplicates only
the authenticated original peer, checks the same short deadline again, and
positively closes that short authority before returning the independent cost
witness. There is no caller-supplied PID, callback, JSON receipt or boolean
that can construct this owner, and no reopening by PID.

The cost duplicate does not extend the readiness RPC's lifetime. Subsequent
same-handle liveness observations establish only who is measured. The original
provider must still perform actual continuous daily coverage checks and every
normal admission/readiness fence. Capture neither registers a Job nor permits
fixture creation. The aggregate provider must call capture before any fixture
creation and retain it through measurement; the current absent aggregate
provider has not yet exercised that ordering in a native run.

The original capture owner is retained before its first RPC/duplicate attempt.
One demand cannot start a replacement capture, including after a failure or
positive close. Original outcome/exception owners are pinned independently of
mutable object attributes. Capture errors retain `error.daily_monitor_owner`.
Original process owners also retain their exact native backend, lock, handle,
identity and (for a failed transfer) output cell. Replacing the numeric handle
inside the same Python wrapper cannot change what is observed or closed.
Positive close acknowledgements and unknown outcomes are retained separately
from mutable wrapper fields; a later field edit cannot recreate a closed owner
or erase an unknown close.
Cleanup follows only the fixed client's explicit ownership links; unrelated
Python exception context/cause remains retained but grants no cleanup authority.
`assert_original()` returns the exact original live cost handle or raises;
`close()` settles only original query/transport owners and never calls connect,
admission, demand release or a control API. Explicit native close FALSE can
retry only where the original owner supports it. Unknown duplicate or close
remains pending; neither absence of an output nor a foreign object's `closed`
field is proof of cleanup. A failed connection acquisition that did not return
an original native connection cannot be reconstructed or cleared by this helper.
Its original error and any transport-registry custody remain retained.

After all originals positively close, interrupted local finish bookkeeping
replays without native calls. `custody_pending` is false only after that finish;
its original binding remains verifiable after the actual daily demand release
closes the caller and clears its launch claim. The P4 runner pins the session,
monitor and witness during opening, rechecks that original during ongoing
coverage, and refuses retirement completion until the same monitor is closed.
The opening pin uses the exact pair returned by inventory validation and
rechecks the session before probe creation; rereading a changing property
cannot substitute a different monitor after validation.
The provider must close this monitor before releasing its daily allocation;
the runner's completion check does not itself authorize that release.

Portable tests use actual isolated admission/release SQL and the real readiness
client protocol. Native process and pipe backends are explicit synthetic
collaborators; known-FALSE versus unknown cleanup also exercises the actual
`NativePipeConnection` owner. These tests are source verification only. This
slice does not supply `open_overhead_session`, actual host/cohort launch and
adoption, authenticated guardian/telemetry transport, bounded aggregate demand
lifecycle, or measured storage/overhead evidence. The 600-second scale windows,
3,600-second stress, ten-managed-Job limit and all capability gates are unchanged.

## Actual host measurement contract

Each measured tick invokes the original `OperationalHelperHost.run_once()` and
the production report path. Its normal enrollment refresh, registry read, native
open/release, memory scanner, operator poll, metrics serialization and enqueue
belong inside the timed bracket. The asynchronous writer's work is charged in
the same original process CPU and Private Commit measurements. The engine defers only the sleep
operation. Transparent taps count the actual operator invocation and capture the
exact original machine observation without changing it. All original callbacks
are retained and restored exactly; the engine performs the
actual wait outside that bracket, and records the native deadline and before/after
wait timestamps. An unresolved callback replacement, original sink receipt, or cleanup
keeps the original owner and fails the run.

For 1/10 Jobs, the actual host enrolls exactly the measured canonical scopes.
For 50, the same actual host still enrolls only ten managed Jobs; forty additional
native QUERY-only stress fixtures run in four bounded sampler shards in that same
charged helper process. Those forty fixtures must be absent from the managed
execution registry. No second helper row or fifty-Job production enrollment is
permitted. The authentic aggregate owner retains their daily demand and native
cleanup just as it retains the ten managed scopes.

All samplers share one original `NativeScanBudget` per outer tick, starting at
the native bracket's first timestamp, with at most 256 members and 100 ms total.
The production source still performs its own `begin_sample`; the shared budget
can only constrain work and never supplies memory readings. Duplicate native
identities across shards invalidate the affected measurement rather than credit
an earlier shard's subtraction. One actual host machine sample is shared with
the supplementary shards; no fabricated frame or repeated short delta is used.

The scale artifact must include actual host identity and scope, original
iteration range, completed registry-refresh/report/operator-poll counts, report
enqueue bytes and sequences, and per-sample pacing observations. Exact later
write receipts must prove those required reports persisted. The strict P4 verifier rejects old
core-only artifacts; a provider boolean cannot certify host coverage. Raw traces
retain the detailed observations behind these counts.

Normal host reports are included in runtime log growth. They are not discarded
or relabeled producer evidence to satisfy the leak comparison. If actual reports
make the existing idle-after log-byte rule fail, that remains a measured failure
until the formal contract or real bounded logging behavior is separately resolved.

## What is actually measured

- Scales 1, 10 and 50 each run for at least 600 actual interrupt-time seconds.
  Fifty uses the original ten-Job host and four bounded query-only shards.
  It never registers 50 managed Jobs or
  changes the production enrollment limit. One native machine sample is shared
  across shards in a tick; repeated millisecond machine windows are not used.
- Native `GetProcessTimes` cumulative CPU counters and exact identities cover
  the helper/measurement process, real guardian, every waiting wrapper, actual
  supervisor, accounting keeper and daily activation/readiness process.
  Role incidence is preserved while exact identities are deduplicated; a helper,
  guardian or wrapper cannot alias a cheaper observer role.
  Fixture workload CPU is excluded. Reads borrow original retained handles,
  lock their custody and verify native identity/liveness. No PID is reopened.
- `GetProcessMemoryInfo(PROCESS_MEMORY_COUNTERS_EX)` supplies current private
  Commit and its lifetime peak. Scale budget observations use lifetime peaks as
  conservative upper bounds, including peaks between samples. Entire waiting
  wrapper host peaks are charged as the additional wrapper cost; no arbitrary
  baseline process is subtracted. Idle leak comparisons use current Commit.
  The official helper+guardian peak is recorded separately from all resident
  observer peaks and total peaks. As a conservative interpretation of §11.2,
  **all** non-wrapper residents must fit the existing 160 MiB bucket; no extra
  allowance is added for supervisor/keeper/readiness. All unique observers also
  share the existing 0.05/0.10/0.25 CPU-unit limits. Per-process peak vectors let
  the verifier recompute those totals in the exact recorded inventory order.
- `GetProcessHandleCount`, actual read-only runtime SQL row counts and runtime
  log byte counts form the leak trace. The same cohort is measured after equal
  idle settling periods (at least 30 seconds and enough ticks to fill the bounded
  sample ring) before and after at least 3,600 seconds of
  stress. Historical records/logs are not deleted to make the result pass.
- The real `ShadowHelper` and `FrameSampler` run once per tick. Missed deadlines
  are dropped; no catch-up loop is used. Tick brackets exclude the pacing sleep.
  Ten cold and ten warm wrapper launches are measured separately, excluding
  completed admission waits from the measured bracket.
- A real interposer installed on each borrowed Job backend observes and denies
  any attempted native Set. Guardian instrumentation is independently required
  through its authenticated bridge. An empty list or uninstrumented default
  zero cannot assert zero writes. Any attempt fails the run.

The documented Windows memory structure is two DWORD fields followed by nine
SIZE_T fields: x64 size 80 / `PrivateUsage` offset 72, x86 size 44 / offset 40.
The existing probe already contained `PeakPagefileUsage`; this change uses an
explicit 32-bit DWORD representation and adds layout tests. This is not evidence
that an earlier native measurement was wrong. Microsoft documents current and
lifetime peak private Commit in
[PROCESS_MEMORY_COUNTERS_EX](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex).

The actual-host contract above supersedes the earlier direct core-loop
measurement. The old standalone core producer has been removed. Source and
portable tests now express the contract. Central verification passed 155 tests
in 12.967 seconds (zero failures, errors or skips), covering the overhead runner,
actual-host adapter and both capability-evidence modules. The run used normal
daily Sentinel admission and the protected dirty baseline. No native host
overhead result has been certified.

The original 50 ms operator accept wait has since been replaced by retained
nonblocking polling in production source. The real poll remains inside the
measured tick; its source tests are not a measured p95 result. The same 10-Job
p95 ≤50 ms gate still applies, with pipe custody and request latency preserved.

## Honest remaining native sampling gap

`JobHandleSource` now has a bounded native member scanner. This runner reads its
same-frame frozen results for inaccessible-identity and scan-budget-timeout
counts, in addition to actual membership changes and unknown-memory frames.
Unobserved cases remain zero. It does **not** turn synthetic exceptions, sleeps or fabricated counters
into the positive native cases required by the P4 verifier.

Consequently, a completed cost run still fails the current P4 gate until those
real sampling cases are observed. Membership changes also must
come from real cooperative fixture churn; static Jobs do not pass that case.
Implementing the native member scanner alone is not evidence of those cases.
EX2 unavailability must keep subtraction conservative; shared RSS is not a
replacement.

## Artifacts and verification boundary

Each scale, leak run and wrapper trial group saves its actual raw data in a new
subdirectory. Buffered JSONL traces have a fixed 4 MiB bound and fsync only when
closed. They are excluded from monitored runtime log size. Files are created
exclusively; existing evidence is never overwritten and active logs are never
rotated. Complete raw `P4-data.json` is written before gate validation so failed
measurements survive. Only validated data is returned for artifact-v1 publication.
The P4 artifact has a fixed 2 MiB limit selected by the caller's expected gate
before reading; other gate artifacts and IPC retain their prior limits. The
limit does not follow an untrusted payload label or filename and cannot grow
automatically. Truncated, malformed and oversized artifacts fail closed.

Portable unit tests cover exact CPU identity joins, counter reversal, conservative
peak attribution, missing-case preservation, native audit replay/freshness,
no-provider refusal before side effects, retained custody after interruption,
read-only footprint accounting and both Windows structure layouts. They prove
those software behaviors only, not cost, recovery, capability or a passed P4.

The sink-integration regression uses closed P4 data `schema_version=2`.
Every scale, the wrapper group and the leak experiment carry original sink
offer/write counters and complete bounded receipt coverage. The verifier
reconstructs the unique shared file inventory chain from an initially empty
isolated store to a fresh independently locked final inventory, including the
one-byte lock metadata. Required reports must be persisted, not merely queued or
superseded. Recorder gaps, replacement, degraded storage, clock regression and
counter/byte discrepancies fail the evidence. Original receipt rings and the
bounded recorder's memory remain in the measured monitoring cohort. No fake
inventory, prefill, report suppression, imported stream or empty log replacement
is accepted.

Trace retention is also byte-bounded before insertion: at most the existing
2 MiB artifact allowance per trace, including a fixed 64 KiB framing reserve.
Only new bounded receipts are serialized for incremental accounting; repeated
ring observations do not repeatedly serialize the retained history. A refused
receipt permanently marks that trace incomplete. The unchanged whole-artifact
2 MiB check still applies across all scopes and can refuse the combined output.
This prevents count-bounded full inventories from accumulating over 100 MiB;
it does not prove that full native runs fit the final artifact or memory budget.
No observer allocation is excluded from cost, and the strict idle Private
Commit comparison can still fail if retained evidence grows during the run.

This source integration **retains the strict idle-after log-byte comparison**.
The proposed log-only deviation in `P4-BOUNDED-TELEMETRY-CONTRACT.md` requires
additional native storage-fault/rotation/recovery-preservation evidence and a
reviewed interpretation of unexercised native quota/age boundaries. It is not
enabled by a schema version or bounded-policy constant. The authenticated
aggregate fixture provider remains missing, so this producer has not executed
or passed P4. Central source regression on 2026-09-24 passed **259 tests in
13.765 seconds, zero failures/errors/skips**, across the seven telemetry,
host/runner and capability modules. Full private log:
`.local-adaptive/p4-sink-regression-20260924-1.log`. The tested tree includes
protected dirty baseline and adjacent readiness/preparation source; this is
not clean-clone or native acceptance evidence.

On 2026-09-22, the central admitted S1/S2/inventory/P4/S3 portable batch passed
161 tests in 41.676 seconds (zero failures/errors/skips), including the 39
overhead tests. The separate P4/P6 batch passed 184 tests in 0.610 seconds.
Earlier audit fixtures omitted the explicit interposer installation and left
a setup SQLite connection open; those fixtures were corrected while preserving
the denied-Set assertions. No native overhead run or daily change was made.
Protected dirty baseline and adjacent source changes were present; clean-clone
verification is not claimed.
