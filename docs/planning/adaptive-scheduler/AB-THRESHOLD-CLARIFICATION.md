# A/B threshold clarification C1 and C2

Status: a clarification adopted on 2026-09-20 by the repository owner's
instruction. It is not part of IMPLEMENTATION-PLAN.md and that file was not
edited. It applies to the harness in `tests/benchmarks/adaptive_ab.py` only.

No A/B data has been measured. Variant B needs the CPU actuator running on a
supported host, and that has not happened, so every comparison still reports
NOT_MEASURED. What follows changes
how a future measured run would be judged, nothing about any result today.

## What plan 11.3 leaves without a number

Plan section 11.3 gives numbers for the A1 to B comparison in each scenario
class. It gives none for the other two comparisons:

- A0 to A1, the cost of the observer, the new launch path and the accounting
  change. The plan names no tolerance at all.
- A0 to B, the end to end user veto. The plan says only that B is not promoted
  if the overall cost or the interaction effect regresses, with no tolerance
  attached.

Before this clarification the harness reported A0 to A1 as NO_THRESHOLD_DEFINED
and applied a zero tolerance to A0 to B. Zero tolerance is unusable in practice,
because capping a background Job raises that Job's makespan by design, so the
veto would reject every possible B.

## C1: A0 to A1

A1 sets no CPU cap. A variant that never caps anything should look like the
plan's neutral scenarios, so A0 to A1 is held to the plan 11.3 neutral rule:

- median foreground p95 degradation at most 5 percent;
- median makespan degradation at most 5 percent.

Plan 11.2 also gives monitor CPU limits of 0.05, 0.10 and 0.25 CPU units for 1,
10 and 50 enrolled Jobs. The run record schema carries no enrolled Job count, so
that check stays NOT_APPLICABLE and prints the measured value for a human. If a
Job count is added to the record later, the rule is: use the threshold of the
next larger listed count, never interpolate, and report NOT_APPLICABLE above 50.

## C2: A0 to B

The veto keeps a zero tolerance on interaction, because B may not make the
foreground worse than the live baseline a person already has. The batch cost
side uses the plan's own tolerance for that scenario class.

In CPU rule scenarios:

- median foreground p95 change at most 0;
- median makespan degradation at most 15 percent;
- median throughput drop at most 10 percent.

In neutral rule scenarios:

- median foreground p95 change at most 0;
- median makespan degradation at most 5 percent.

Scenario classes that plan 11.3 lists no tolerance for, such as mixed roles,
report NOT_APPLICABLE and leave the judgement to a human.

## Every number here is an existing plan number

5 percent is the plan 11.3 neutral tolerance. 15 percent and 10 percent are the
plan 11.3 CPU scenario batch tolerances. 0.05, 0.10 and 0.25 CPU units are the
plan 11.2 monitor CPU rows. Nothing was invented. What is new is only the
mapping of those numbers onto two comparisons the plan left open, and every
check produced under the mapping says so in its detail text, labelled
"clarification C1 (not in plan 11.3)" or "clarification C2 (not in plan 11.3)".

## How to revert

The clarification is one commit. Revert it and the harness returns to
NO_THRESHOLD_DEFINED for A0 to A1 and to the zero tolerance A0 to B veto. The
touched files are `tests/benchmarks/adaptive_ab.py`, `tests/test_adaptive_ab.py`,
this file, and the plan gaps section of `ACCEPTANCE-RESULTS.md`.
