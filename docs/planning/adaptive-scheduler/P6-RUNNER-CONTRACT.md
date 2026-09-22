# P6 schedule, evidence schema and external measurement producer

Status: the initial source foundation and portable tests were verified. The
subsequent whole-matrix coordinator, raw reducer and scope fixture await central
tests; native execution has not been performed. This document does not close P6, grant a capability, or
authorize daily-runtime activation. Formal plan §11.1–§11.4 remains authoritative.

## Scope and current limit

`tests/benchmarks/adaptive_ab.py` owns closed run records, pairing, arithmetic and
reporting. `tests/benchmarks/adaptive_runner.py` plus `scripts/adaptive-ab.py`
provide an exclusive schedule artifact, strict report ingestion, and an actual
bounded public-fixture measurement flow. `tests/fixtures/win32_ui_probe.py`
provides native message-loop observations. No command enables adaptive mode,
starts an actuator, modifies a daily database/configuration, creates an
exemption, changes reserves or deploys a source tree.

The raw fixture producer is deliberately named `measure-fixture`. It is not a
complete A0/A1/B orchestrator. It cannot establish the original A0 collector and
wrapper path, managed A1/B lifecycle, complete native cap write/readback audit,
monitoring-process cost, or clean between-run CPU/Commit return merely by
running a Python command. Those are explicit missing qualifications in its
artifact; it never fabricates a `RunRecord` with zeros or `True` preconditions.

The subsequent source adds `adaptive_orchestrator.py` and
`adaptive_measurements.py`. `run-matrix` coordinates the complete experiment
through an original in-process native pass owner; it does not upgrade the raw
fixture command into an A/B result. The required real provider bridge is still
unavailable. The coordinator, reducers and native workload fixtures are
independently implemented and remain executable only when that bridge supplies
actual authority and observations.

The current continuous-admission prerequisite rejects execution. The real daily
Coordinator's live consumer cohort and persistent demand floor must be deployed
and verified by a separately authorized operational change. An isolated test DB,
environment flag, capacity snapshot, signed-looking JSON, or an ordinary
heartbeat cannot replace that requirement. The producer must retain the real
provider's original in-process authority through fixture cleanup. A failed
finish retains that same authority, retries only cleanup, starts no new work,
and cannot become an ordinary successful process exit.

## Fixed pairing contract

Each record has explicit `comparison`, `scenario`, `scenario_class`,
`pair_index`, `variant`, `slot_id`, `seed`, `run_id` and `order_position`.
`slot_id` is the SHA-256 digest of comparison/scenario/class/pair. A pair has
two variant slots; an A0 observation from A0/A1 cannot also be reused by A0/B.

The independently saved schedule is regenerated from its seed and compared
exactly. A reported order is not proof of the predeclared order. A missing
schedule, duplicate slot/run, changed order, wrong variant, inconsistent seed,
or a changed scenario class cannot establish a valid pair. At least ten pairs
are required. Increasing the count produces a newly preregistered schedule;
observed outcomes do not choose a replacement order.

The overall result requires every named scenario crossed with all comparisons:

| Scenario | A0/A1 | A1/B | A0/B |
| --- | --- | --- | --- |
| cpu_bound_build | required | required | required |
| io_bound_install | required | required | required |
| memory_heavy_test | required | required | required |
| no_pressure_idle | required | required | required |
| unmanaged_cpu_pressure | required | required | required |
| mixed_exempt_background_protected | required | required | required |
| mixed_root_and_child_durations | required | required | required |

Twenty-one analyses and at least 420 distinct run records are needed for the
minimum matrix. Three comparisons distributed over unrelated scenarios are
insufficient. Source authentication and native gate verification remain separate
from schema validation; a caller writing `measured` into JSON is not L4 evidence.

## Conditions and reserve attribution

Fixed conditions include commit, OS build, N, power plan, cache state, dataset
SHA-256, task count, UI-probe SHA-256, collector-scope SHA-256, and a complete
three-variant build digest map. The same scenario retains those pins across
all pairs and comparisons. Recorded thermal/power anomalies exclude a run.
Unmeasured thermal/power state must not be guessed as normal by the producer.

Physical and Commit minima are separate fields. Each has an attribution and an
evidence identifier. `within_reserve` requires at least 4096 MiB. A deficit
attributed to new admission overbooking fails. Existing, unmanaged, exempt or
mixed external load is reported distinctly and never described as prevented by
B. Unknown attribution remains unverified. This does not introduce an allowance
to launch a fixture below reserves: the raw producer stops cooperatively when
its observed physical or Commit reserve is lost.

## Native cap evidence

Cap absence is based on native ENABLE events and intervals, not policy state
names. `RECOVERING` with a baseline rate is still enabled. Even a zero-duration
observed enable event is a cap. Records require hashes of the full native write
audit and Query readbacks. `native_cap_audit_complete` means continuous write
coverage plus readback coverage; periodic samples alone cannot prove no short
cap occurred. Missing coverage is unverified. A0/A1 Sentinel caps fail, and any
unrelated B cap in a neutral scenario fails.

Native producer integration must bind audit/readback artifacts to exact Job
identities and run intervals. The schema does not make arbitrary trace files
authoritative. The capability authority must verify the original artifacts
before consuming the analysis for any future promotion decision.

## Preregistered noise estimator

Neutral checks need independent baseline-variant repeat pairs. For each metric,
the empirical envelope is the maximum absolute paired relative change:

`max(abs((repeat - baseline) / baseline))`

At least ten same-variant repeat pairs with matching conditions, comparison,
scenario and seed are required. Calibration run IDs cannot be reused as treatment
run IDs. Synthetic calibration is not measured evidence. The paired median
regression must be at most 5% and no greater than that observed envelope.
An envelope above 5% is too noisy for acceptance, requiring more evidence; it
does not loosen the ceiling. This is a conservative, explicitly chosen empirical
rule, not a confidence interval or statistical guarantee.

C1/C2 from the existing AB threshold clarification remain labelled as such.
The formal plan does not supply numeric performance thresholds for unmanaged
pressure, mixed roles or mixed lifetimes; a complete matrix still reports
`NO_THRESHOLD_DEFINED` for those comparisons. Qualitative safety evidence and a
reviewed release decision remain necessary. This patch does not invent numbers
or remove the capability authority's LIMITED promotion block.

## Actual public fixtures and UI probe

The workload fixture executes fixed SHA-256 unittest assertions, bounded memory
test assertions, a normal idle command, or a real offline `pip install` of a
deterministic public wheel. It uses at most four children, 128 MiB test allocation
per child, and at most eight 8 MiB installations per child. The wheel has no
dependencies, setup code, network fetches, or entry points. Parameters and dataset
are recorded. These are public tool/fixture observations, not claims about the
user's private repository build performance.

CPU/memory/idle children have a cooperative deadline and stop file. Every child
is waited for; no kill or periodic suspension is used. A pip process that fails
to return retains its original owner and prevents the measurement from ending
successfully. The observer deadline is not permission to abandon a live child.

The Win32 probe runs directly with `C:\Python313\python.exe`. It verifies that
its own process is outside every Job and has Normal priority at startup, each
dispatch, and completion. It neither changes priority nor inspects another
window. It records enqueue-to-WndProc time and actual OS-generated internal
WM_PAINT scheduling using BeginPaint/EndPaint. The hidden, nonactivating window
is a UI-thread proxy; it does not measure compositor, real keyboard-to-screen,
RDP, or user-application latency. No user content is captured.

Only complete native observations with successful cleanup receive the probe's
`measured` status. Incomplete samples, wrong Job/priority context, unsupported
platform, API errors or cleanup failures cannot receive that status. Raw
timestamps are retained alongside p50/p95/p99 distributions. All output files
are new, exclusive artifacts; earlier evidence is never silently replaced.

The raw fixture observer collects real machine CPU counter endpoints and separate
physical/Commit headroom. An unavailable measurement remains unavailable. It
stops launching or tightening nothing: it owns no control mechanism at all.
It requests cooperative fixture exit on reserve loss and retains handles until
exit. The other three scenario fixtures need the managed native orchestrator's
scope/role/exemption and root-child authority; the CLI reports them unsupported
instead of simulating those semantics.

## Commands and remaining integration

From an ordinary external Windows console, first create an immutable schedule:

```powershell
C:\Python313\python.exe scripts/adaptive-ab.py schedule --seed p6-review-001 --pairs 10 --output C:\isolated\p6\schedule.json
```

The parent directory must exist. All following paths refer to isolated test
artifacts, never the production data directory. A raw measurement invocation is:

```powershell
C:\Python313\python.exe scripts/adaptive-ab.py measure-fixture --scenario cpu_bound_build --tasks 2 --units 10000 --seconds 90 --evidence-dir C:\isolated\p6\new-observation
```

This currently records a blocked prerequisite before any fixture launch unless
the actual retained daily continuous-admission provider is available. Passing an
alternate data directory is not offered. Four public fixture scenarios are
supported by the raw command; it continues to reject the three scope-sensitive
scenarios. The whole-matrix coordinator specifies all seven. Its separate native
scope fixture implements unmanaged CPU and root/child lifetimes, while actual
mixed-role/grant construction belongs to the retained native bridge.

Once verified native producers supply the complete strict RunRecord and noise
schemas, the read-only report command is:

```powershell
C:\Python313\python.exe scripts/adaptive-ab.py analyze --schedule C:\isolated\p6\schedule.json --records C:\isolated\p6\records.json --noise C:\isolated\p6\noise.json --output C:\isolated\p6\report.md
```

Required integration remains: actual A0/A1/B launch/collector equivalence,
retained daily admission, isolated host startup/drain and capability scope,
native cap write/readback audit, exact monitor/wrapper cost coverage, queue/state
intervals, between-run native empty/disabled and baseline return, three
scope-sensitive scenarios, and fixed non-private IDE/terminal interaction
observations. None is replaced by portable test results or a `measured` label.

## Whole-matrix execution contract

`register-matrix` creates an immutable registration containing the seed, pair
count, actual source-byte hashes (including uncommitted implementation), policy
profile hash, capability bundle hash, baseline-source-manifest hash and cache
condition. These pins describe intended measurements; they are not native
authority. The real bridge must check them against the actual running cohort,
original baseline and capability scope before starting.

The fixed matrix has seven scenarios and all three comparisons. At the minimum
ten pairs it executes 420 comparison runs plus 420 independent same-baseline
noise runs. Calibration is preregistered and collected before comparison runs;
no treatment outcome selects its calibration. Every run gets a deterministic
unique UUID derived from registration/comparison/scenario/pair/variant/purpose
and repeat index. Only one episode owns native workload scope at a time.

Each episode persists its intent before opening authority or launching. The
bridge registers its own custody before any side effect in `open_episode`.
The coordinator verifies baseline, calls `start()` exactly once, captures real
observations, then requires positive restore, native empty, bookkeeping and
custody cleanup before reducing data or starting the next episode. A failed
sample, unsafe native result, disk-write failure or interruption does not retry
the workload. Recovery holds the same original pass and episode owners. Missing,
unknown or failed custody metadata is not a positive cleanup result.

The native bridge API is narrow and fixed to this experiment:

```text
real_daily_coverage.open_p6_pass(registration, directory) -> original pass owner
pass: assert_unchanged(), open_episode(spec, directory), recover_once(), close()
pass: pending_custody (explicit bool; False only after positive settlement)
episode: run_id, verify_baseline(), start(), observe(), restore_and_drain()
episode: cleanup_complete, finish_trace() -> NativeEpisodeObservation
```

`pending_custody` reports unresolved or live episode custody; holding the pass
registration/fence alone does not make it true. `cleanup_complete` is a retained
native result, not a JSON receipt. The pass owner retains partial construction
before returning an episode. Invalid bridge returns, admission exceptions that
retain an owner, or failure while recording a blocked prerequisite preserve the
original coverage authority. A rejected unexpected native object is retained
as unverified custody rather than given a guessed recovery method.
Pass and daily coverage obligations are both retained: settling only the pass
cannot publish a complete result or finish recovery. Separately retained
acquisition custody remains a blocker too. A broken console or failure to write
the blocked artifact cannot discard those original objects.

This bridge is under implementation in the shared native validation work. Its
absence currently stops `run-matrix` before a workload. A static prerequisite
report, ordinary reservation ID, callback returning success, or alternate DB
cannot implement it.

The native baseline helper requires ten contiguous measured reference windows
and five contiguous return windows with the same clock/conditions. Return CPU
and Commit must fit the previously observed maxima, with native prior scopes
empty, caps disabled, original cleanup settled, and physical/Commit reserves
intact. No guessed tolerance or value from capped usage changes this envelope.
The bridge must produce these observations from actual native/read-only sources;
the pure helper itself cannot prove them.

The raw reducer validates complete UI/machine/process/state/lifecycle coverage.
Admission wait is included in batch makespan, and the last surviving child's
finish determines the end. Independently enumerated monitor and wrapper
identities must have exact counter coverage; missing identities cannot become
zero cost. CPU includes bounded collection tails, and Private Commit is clearly
labelled a sum-of-process-peaks upper bound, not a simultaneous batch peak.
Precise Job/control coverage may be zero for unmanaged work while its raw
observations remain complete.

Each demand also pins its original owner, role, priority and scope artifact.
Enabled caps require owned background P2/P3 work. A clock/policy/epoch/logon-bound
grant audit covers the full execution scope with contiguous revisioned windows,
explicit original authorization and unchanged original deadlines; cap overlap
with a live scoped grant rejects the trace. These checks observe existing grant
authority and never create, renew or revoke a lease.

For A0 or unmanaged work outside a Job, every original live fixture member needs
native `IsProcessInJob(NULL)=False` observations covering its lifetime. No disabled
Job query is manufactured for this scope. A trace with no owned Jobs may honestly
have empty cap execution, event and writer inventories; missing process or grant
observations still cannot become empty evidence.

Native provenance binds raw trace, run, clock, artifacts, variant, seed, purpose
and comparison slot where applicable. Calibration has its own purpose and no
invented comparison slot. The reducer's provenance checks describe integrity
and binding, not proof that an arbitrary caller invoked Windows APIs. Only the
native bridge issues those receipts, and later gate verification must inspect
the original artifacts.

Per-episode safety stops the remaining matrix for API errors, incomplete audit,
prohibited A0/A1 or neutral B caps, overlapping native victims, new-admission
reserve losses or unknown attribution. The full matrix result aggregates every
required run and separately exposes the analyzer verdict. Even a complete
measured matrix cannot itself enable LIMITED mode; missing qualitative policy
for mixed/unmanaged performance remains explicit.

Example source-pinned registration and execution:

```powershell
C:\Python313\python.exe scripts/adaptive-ab.py register-matrix --seed p6-review-001 --pairs 10 --profile-file C:\isolated\p6\profile.json --capability-bundle C:\isolated\capability\bundle.json --baseline-source-manifest C:\isolated\p6\baseline-source.json --cache-state warm --output C:\isolated\p6\registration.json
C:\Python313\python.exe scripts/adaptive-ab.py run-matrix --registration C:\isolated\p6\registration.json --evidence-dir C:\isolated\p6\new-pass
```

No source, config, DB, Scheduled Task or policy entrypoint is deployed by these
commands. Native trials continue to require the separate proven authority and
authorized runtime preparation.

Portable validation targets:

```powershell
C:\Python313\python.exe -m unittest tests.test_adaptive_ab tests.test_adaptive_runner tests.test_win32_ui_probe -q
```

On 2026-09-22 the coordinator ran these three modules together with
`tests.test_adaptive_overhead_runner`: **184 tests passed in 0.610 seconds,
zero failures/errors/skips**, through normal daily Sentinel admission. The
earlier Windows default-encoding fixture error was fixed by explicitly reading
the producer's UTF-8 report. P4's native-boundary fixtures were corrected to
install their audit interposer and close their setup SQLite connection; audit
assertions were preserved. Those P4 sources remain a separate integration.

The tests used the protected dirty integration baseline and adjacent uncommitted
work. They do not establish a clean-clone run, complete A0/A1/B orchestration,
native measurement, or permission to promote. No native measurement/control or
daily runtime change was performed.

Additional central targets for the subsequent source (not run by the subtask):

```powershell
C:\Python313\python.exe -m unittest tests.test_adaptive_orchestrator tests.test_adaptive_measurements tests.test_adaptive_scope_workload -q
```
