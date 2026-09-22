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
| `guardian` | Retained exact witness for a real isolated guardian host. A sleeping fixture must not be labeled guardian. |
| `wrappers` | Exactly `jobs` original witnesses for real waiting wrapper hosts, all retained and continuously covered. |
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
retains unknown creation/readiness outcomes. Cold means a newly created wrapper
host; warm means the defined already initialized host/cache path. Both modes
must invoke the actual admission-only wrapper implementation. Their source and
launch topology belong in the same native evidence run as the artifact.

An exception during bridge creation leaves custody in the original coverage
owner. Once a session exists, measurement or cleanup failure raises
`OverheadUnsettled` with that exact coverage/session and local query owners.
An interrupt is re-raised with the same retained owner attached. The external
orchestrator must remain resident and recover those originals; it must not
serialize a receipt, reconstruct owners from PIDs or exit with live obligations.

## What is actually measured

- Scales 1, 10 and 50 each run for at least 600 actual interrupt-time seconds.
  Fifty uses five separately bounded read-only sampler shards (or smaller shards
  if the profile allows fewer than ten). It never registers 50 managed Jobs or
  changes the production enrollment limit. One native machine sample is shared
  across shards in a tick; repeated millisecond machine windows are not used.
- Native `GetProcessTimes` cumulative CPU counters and exact identities cover
  the helper/measurement process, real guardian and every waiting wrapper.
  Fixture workload CPU is excluded. Reads borrow original retained handles,
  lock their custody and verify native identity/liveness. No PID is reopened.
- `GetProcessMemoryInfo(PROCESS_MEMORY_COUNTERS_EX)` supplies current private
  Commit and its lifetime peak. Scale budget observations use lifetime peaks as
  conservative upper bounds, including peaks between samples. Entire waiting
  wrapper host peaks are charged as the additional wrapper cost; no arbitrary
  baseline process is subtracted. Idle leak comparisons use current Commit.
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

The direct shadow sampling engine does not yet include the resident
`HelperHost` registry-refresh/reporting path. Its implementation must be measured
in the same charged helper cohort before treating this core-loop result as the
complete host overhead gate. The aggregate bridge cannot certify this gap merely
by returning an approval flag.

## Honest remaining native sampling gap

Current `JobHandleSource` samples native Job accounting and intentionally leaves
per-Job memory unknown. There is no native per-member memory scan implementation
to produce inaccessible-identity or scan-budget-timeout cases. The runner records
actual membership changes, actual unknown-memory frames and zero unobserved
cases. It does **not** turn synthetic exceptions, sleeps or fabricated counters
into the positive native cases required by the P4 verifier.

Consequently, a completed cost run still fails the current P4 gate until those
real sampling cases are implemented and observed. Membership changes also must
come from real cooperative fixture churn; static Jobs do not pass that case.
Implementing the native member scanner is separate from this measurement source.
EX2 unavailability must keep subtraction conservative; shared RSS is not a
replacement.

## Artifacts and verification boundary

Each scale, leak run and wrapper trial group saves its actual raw data in a new
subdirectory. Buffered JSONL traces have a fixed 4 MiB bound and fsync only when
closed. They are excluded from monitored runtime log size. Files are created
exclusively; existing evidence is never overwritten and active logs are never
rotated. Complete raw `P4-data.json` is written before gate validation so failed
measurements survive. Only validated data is returned for artifact-v1 publication.

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
