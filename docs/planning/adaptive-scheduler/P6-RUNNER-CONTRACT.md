# P6 schedule, evidence schema and external measurement producer

Status: source foundation and portable tests verified; native execution has
not been performed. This document does not close P6, grant a capability, or
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
implemented; the three scope-sensitive scenarios are explicitly blocked.

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
