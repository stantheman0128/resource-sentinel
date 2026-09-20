# Acceptance results: adaptive scheduler A/B

Status: no A/B data has been measured. This document is an empty template.

Nothing below is a result. Every table is a placeholder, and the verdict is
NOT_MEASURED until measured records replace the placeholders. Do not cite this
file as evidence that the A/B comparison was run, was passed, or was completed.

## Why there is no data yet

Variant B is the A1 build with the approved single victim CPU policy enabled.
No CPU actuator exists yet, so variant B cannot run, and without variant B there
is no A1 to B or A0 to B comparison to report. The plan states plainly that none
of its thresholds have been measured in this round
(IMPLEMENTATION-PLAN.md, section 11.2).

Two rules apply to everything that is eventually written here:

- Without comparable measured A1 and B data, no one may claim the A/B is done.
- Setting a one second or six second timer is not a measurement of reaction time
  or restore time.

## How this document gets filled in

The harness is `tests/benchmarks/adaptive_ab.py`. It builds the schedule,
validates the run records, computes the paired statistics, applies the
thresholds from plan section 11.3, and renders the report that belongs in the
sections below. It launches no workload. A later stage has to implement the
`BenchmarkRunner` protocol to produce measured records; the only runner shipped
today is `DryRunRunner`, which prints the schedule and refuses to return a
record.

Order of work:

1. Fix the commit, the workspace, the dataset, the task count, the cache state
   and the power plan, and record the OS build and the logical processor count.
2. Build the schedule with a seed and record that seed here.
3. Run each slot, one variant at a time, in the scheduled order. Start each run
   only after the previous Job is empty, CPU and Commit are back to baseline,
   and the cap audit reports disabled.
4. Store one run record per run with evidence source `measured`.
5. Render the report and paste it below, exclusions and verdict included.

## Fixed conditions

| Field | Value |
| --- | --- |
| Commit | not recorded |
| OS build | not recorded |
| Logical processors (N) | not recorded |
| Power plan | not recorded |
| Cache state | not recorded |
| Thermal or power anomaly | not recorded |
| Order seed | not recorded |
| Pairs per scenario | plan section 11.3 requires at least 10 |

## Scenario coverage

Plan section 11.3 lists the workload shapes. None has been run.

| Scenario class | Scenario | Measured pairs | Evidence source |
| --- | --- | --- | --- |
| CPU contention | not run | 0 | none |
| I/O bound | not run | 0 | none |
| Memory heavy with a safe ceiling | not run | 0 | none |
| No pressure | not run | 0 | none |
| Unmanaged CPU pressure | not run | 0 | none |
| Mixed exempt, background and protected | not run | 0 | none |
| Mixed root and child durations | not run | 0 | none |

## Comparisons

| Comparison | What it may show | Verdict |
| --- | --- | --- |
| A0 to A1 | cost of the observer, the new launch path and the accounting change | NOT_MEASURED |
| A1 to B | the CPU control itself | NOT_MEASURED |
| A0 to B | whether the end user actually benefits; a veto | NOT_MEASURED |

Overall verdict: NOT_MEASURED.

A1 to B on its own is not enough. Plan section 11.3 requires all three, so that
infrastructure cost cannot be hidden behind a control win.

## Excluded runs

| Run id | Variant | Pair | Reasons |
| --- | --- | --- | --- |
| none | none | none | no runs exist |

Excluded runs are counted and listed here. A run whose precondition failed, or
was never checked, is never quietly folded into a result.

## Rendered report

Paste the output of the harness report renderer here, unedited. Until then:

```text
no report, no measured records exist
```

## Known gaps in the plan

These are places where plan section 11.3 states no number. The harness does not
invent one, so a human has to judge the outcome or the plan has to be amended.

- No numeric threshold for A0 to A1. The harness now applies clarification C1,
  which reuses the plan 11.3 neutral rule of 5 percent. See
  AB-THRESHOLD-CLARIFICATION.md.
- No tolerance for the A0 to B regression veto. The harness now applies
  clarification C2, which reads the veto with the plan's own scenario
  tolerances. See AB-THRESHOLD-CLARIFICATION.md. Both comparisons still report
  NOT_MEASURED, because no data has been collected.
- No threshold for the unmanaged CPU pressure, mixed role and mixed duration
  scenarios.
- "Minimum headroom" is listed without saying whether it is physical or commit.
  The schema carries one field and the report prints it as given.
- No sample size is named above which a statistical guarantee may be claimed, so
  every result is reported as a small sample.

## Sign off

Sign off is blocked. It stays blocked until measured A1 and B records exist, the
three comparisons are rendered here, and the verdict comes from measured data.
