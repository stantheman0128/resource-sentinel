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
| `helper_report_stream` | The original writable UTF-8 text stream backed by a regular file in `log_directory`; the actual host metrics serializer/write/flush runs against it. Provider retains and closes the stream only after host cleanup. |
| `guardian` | Retained exact witness for a real isolated guardian host. A sleeping fixture must not be labeled guardian. |
| `wrappers` | Exactly `jobs` original witnesses for real waiting wrapper hosts, all retained and continuously covered. |
| `monitor_processes` | Tuple of `(role, original VerifiedProcess)` pairs covering exactly one helper, guardian, supervisor, accounting keeper and daily activation/readiness owner, plus every waiting wrapper. The known supervisor/keeper/readiness roles may share an exact process identity; preserve all roles and charge that identity once. No caller-only demand witness may be relabeled as a keeper. |
| `jobs` | Exactly `jobs` pairs of canonical execution ID and retained native `QUERY` Job handle. Fixture owners retain the corresponding original launch/cleanup custody. |
| `scope_nonce`, `context`, `profile_revision` | Exact native scope, current host/logon/topology context, and profile binding. |
| `database`, `log_directory` | Isolated runtime database and bounded runtime logs, distinct from producer raw evidence. The daily admission DB is never supplied here. |
| `assert_daily_coverage()` | Bounded actual daily allocation/adoption check for every fixture and infrastructure member; returns `None` on success. Unknown, stale or lost coverage raises and preserves original owners. |
| `read_guardian_set_audit()` | Authenticated read of the guardian's actual native Set boundary instrumentation, installed before the experiment. Returns typed `NativeSetObservation` bound to the exact peer and scope with advancing sequence, original install tick and cumulative counters. |
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

## Actual host measurement contract

Each measured tick invokes the original `OperationalHelperHost.run_once()` and
the production report path. Its normal enrollment refresh, registry read, native
open/release, memory scanner, operator poll, metrics serialization, file write and
flush all belong inside the timed bracket. The engine defers only the sleep
operation. Transparent taps count the actual operator invocation and capture the
exact original machine observation without changing it. All original callbacks
are retained and restored exactly; the engine performs the
actual wait outside that bracket, and record the native deadline and before/after
wait timestamps. An unresolved callback replacement, stream write, or cleanup
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
bytes, and per-sample pacing observations. The strict P4 verifier rejects old
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
portable tests now express the contract; central verification is pending for
this amendment, and no native host overhead result has been certified.

The current production operator poll has a 50 ms timeout inside `run_once()`.
That wait is included in tick cost and may by itself prevent the unchanged
10-Job p95 ≤50 ms gate from passing. Removing it from measured work would hide
the defect. A separate production change would need a retained asynchronous
accept/read with bounded nonblocking completion polling, preserving pipe cleanup
custody and request latency; this measurement change does not make that change.

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

On 2026-09-22, the central admitted S1/S2/inventory/P4/S3 portable batch passed
161 tests in 41.676 seconds (zero failures/errors/skips), including the 39
overhead tests. The separate P4/P6 batch passed 184 tests in 0.610 seconds.
Earlier audit fixtures omitted the explicit interposer installation and left
a setup SQLite connection open; those fixtures were corrected while preserving
the denied-Set assertions. No native overhead run or daily change was made.
Protected dirty baseline and adjacent source changes were present; clean-clone
verification is not claimed.
