# Memory observability implementation and physical RAM diagnosis

Completed 2026-09-22, Asia/Taipei. Source implementation and scoped tests complete;
daily runtime not deployed. No adaptive P3–P6 promotion is claimed.

## Protected baseline and deliverable

- Dedicated worktree: `.worktrees/memory-observability-20260922`.
- Branch: `codex/memory-observability-20260922`, created from `0b2f378`.
- The live checkout contains extensive pre-existing modified and untracked source.
  Required files were copied to the isolated worktree and preserved separately in
  its private `.local-baseline` directory before editing. Git HEAD is not an
  adequate baseline for these files.
- All nine copied live files still matched their original hashes after work.
  No live collector, dashboard, configuration, Scheduled Task, pagefile setting
  or shared admission policy was modified. Test admission used the real daily
  wrapper and existing capacity policy; no exemption was requested.
- `memory-observability-20260922.patch` contains only this task's changes to nine
  files. Its companion manifest identifies exact baseline and resulting hashes.
  Applying it to a private copy of the baseline was checked with `git apply
  --check`, then applied and all nine resulting texts matched this implementation.
  This patch is against the captured local source, NOT a clean Git HEAD.
- Following the user's explicit commit/push request, this branch publishes the
  task-only implementation patch, hash manifest and this verification report.
  It does not claim that a clean checkout already contains the integrated feature:
  the patch depends on the captured live observability baseline, which is not
  committed in this repository. The full implementation remains in the isolated
  worktree. Importing pre-existing untracked tracker/dashboard work wholesale would
  include changes outside this task, so those files remain unstaged. Do not stage
  `.local-baseline` (private live diagnostic samples). Integration requires the
  existing observability baseline to be reconciled/committed independently.

## Implemented behavior

1. A separate SQLite memory ledger persists all-interval system/private/residual
   changes and Commit-limit/pagefile-allocation changes. Routine start/exit events
   cannot consume its retention quota.
2. Endpoint snapshots provide 1/5/30-minute net growth, including changes below
   the per-event threshold. Snapshot and interval retention have independent
   age/count limits. Gaps, absent baselines and partial counters remain visible.
3. Lifecycle, memory incidents and other events now have independent bounded
   quotas (256/2000/2000). Routine sub-512-MiB starts/exits stay out of the memory
   incident bucket; significant existing-process growth remains recorded.
4. Collector forwards Commit limit, pagefile allocated bytes, and optional kernel
   counters. Optional counters run in a bounded, hidden child, with a 2.5-second
   process wait and existing bounded-query output handling; failure returns null.
   Admission inputs and policies are unchanged.
5. Dashboard separates occupancy from growth, Commit usage from capacity changes,
   and raw from retained pressure state. It displays identity gaps, truncation,
   event history coverage, unknown counters and unverified/shared session mapping.

Primary source changes: `sentinel/memory_ledger.py`, `sentinel/changes.py`,
`scripts/memory-counters.ps1`, `scripts/collect.ps1`, `dashboard/dashboard.html`.
Tests: `tests/test_memory_ledger.py`, `tests/test_memory_counters.ps1`,
`tests/test_change_dashboard.cjs`. User-facing documentation: `docs/resource-changes.md`.

## Review findings repaired

- An inline optional performance query could stall publication: moved into a
  bounded child; a hung isolated probe is terminated and the caller continues.
- Unknown creation times were dropped by the collector: now forwarded, with
  ambiguous PID start/exit and release claims suppressed.
- Duplicate PIDs could be counted twice in totals and last-wins in deltas:
  conservatively excluded with explicit incomplete coverage, independent of order.
- Legacy and new panels disagreed on missing counters: both now report unknown
  complete private deltas/residuals.
- Snapshot truncation could manufacture exits: unmatched lifecycle rows are
  suppressed when either endpoint is truncated.

## Verification

Windows host; Python 3.13; Node; Windows PowerShell. All test commands ran through
the daily `invoke-sentinel.ps1`, P2, CPU 1, RAM 1 GiB, no exemptions. Final run
waited for CPU admission and then completed. All five test reservations checked
afterwards were absent from the active reservation table.

- Baseline: existing 18 Python tracker tests, dashboard assertions and native
  change-tracker integration passed before changes.
- Final: `python -m unittest discover -s tests -p test_changes.py -v`: 18 passed.
- Final: `python -m unittest discover -s tests -p test_memory_ledger.py -v`:
  17 passed. No Python failures/errors/skips.
- `node tests/test_change_dashboard.cjs`: passed including new coverage, gaps,
  missing values, escaping, identity, limit-growth and retention assertions.
- `powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_change_tracker.ps1`:
  passed parse, isolated real export, stale rejection, timeout and probe cleanup.
- `powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_memory_counters.ps1`:
  passed missing/nonfinite/invalid/zero counters and isolated hung-probe timeout,
  continuation and cleanup. No real user process was terminated.
- Actual bounded Windows pool query returned all four counters in 1,851 ms.
  A separate attempt during concurrent testing reached its deadline and correctly
  returned unknown in about 2.8 seconds; it was not counted as successful sampling.
- Isolated 600-process/132-sample ledger benchmark: median 14.50 ms, p95 16.91 ms,
  maximum 25.64 ms; database 11,583,488 bytes; JSON export 21,439 bytes. All three
  windows became comparable. This measures ledger processing, not whole collector
  latency or all seven days of storage. It preceded final coverage-edge fixes.
- Scoped diff whitespace check and nine-file patch reconstruction passed.

Final command output is retained locally in `.local-baseline/verification-final.txt`.
No browser visual inspection or production soak test was performed. No test Job
Objects or CPU limits were created. All fault-test processes were isolated probes
and cleanup assertions passed.

## What occupies physical RAM now

Read-only Windows memory and process performance counters were sampled at
01:37:19 and 01:46:44. These reads are sequential, not an atomic RAM partition.
The later process sample showed private resident memory approximately:

| Application group | Private resident GiB |
| --- | ---: |
| Chrome (75 processes) | 10.01 |
| Memory Compression | 5.78 |
| T3 Code (Alpha) (8 processes) | 1.47 |
| Cursor (15 processes) | 1.33 |
| ChatGPT (12 processes) | 0.83 |
| LINE | 0.68 |
| svchost (106 processes) | 0.59 |
| Discord | 0.48 |
| Claude (17 processes) | 0.47 |
| Windows Defender / MsMpEng | 0.40 |

At the earlier sample, paged pool resident bytes were about 6.90 GiB, nonpaged
pool about 2.90 GiB, and system cache resident bytes about 2.30 GiB. These system
categories must not be blindly added to process working sets. Chrome's private
Commit at the later sample was 17.35 GiB despite 10.01 GiB private resident RAM;
Claude's was 3.19 GiB despite 0.47 GiB private resident RAM. This is why the previous
Commit inventory was not a physical-RAM inventory.

Across roughly 9 minutes 26 seconds, paged pool grew 19.25 MiB and nonpaged pool
14.11 MiB. Two endpoints do not establish sustained leakage or rule it out.
Windows reported boot time September 13 04:30, so these system allocations have
had about nine days to accumulate. A pool tag / driver-level attribution has not
been obtained. No speculative driver repair or service shutdown was performed.

Standby caches belong to available/reclaimable memory; do not label them all as
unavailable RAM or promise that clearing them fixes Commit pressure. The later
memory-counter read reported 16.72 GiB available, while the separate OS query
reported about 47.26 GiB physical used. Small differences are sampling skew.

References:
- https://learn.microsoft.com/en-us/windows-hardware/test/assessments/results-for-the-memory-footprint-assessment
- https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-performance-problems-in-windows

## Next boundary

Reconcile the pre-existing observability source baseline before normal code
commits; apply only the reviewed delta against matching hashes. Enabling the
daily collector/dashboard is a separate deployment step under the user's prior
no-production-change boundary. Once enabled, 30-minute history needs 30 minutes
of contiguous real samples; no historical per-process data can be reconstructed
from the previously evicted events. The current kernel allocation owner remains
unattributed pending targeted pool-tag evidence.
