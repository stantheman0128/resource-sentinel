# Bounded native member memory capture

This implements the member-memory path in formal plan §5.3–§5.5. It is query
telemetry, not a new control surface or proof that the P4 overhead gate passed.
Native timing, inaccessible-member and timeout measurements are produced by the
isolated P4 runner. Portable fixtures only verify contracts and failure paths.

`HelperHost` configures `NativeMemberMemoryScanner` after its native machine
source and shared interrupt-time clock are ready. `JobSampler` invokes the
optional `JobHandleSource.begin_sample(started_tick, execution_ids)` once per
capture, before the usual cumulative CPU reads. The source samples only retained
enrolled QUERY Jobs, outside SQLite and POLICY scopes. Explicit in-process
clock/machine fixtures remain portable and can inject an explicit scanner.

## Bounds and exact membership

One `NativeScanBudget` covers the capture: at most 256 managed records and a
100 ms deadline, checked before and after native operations. Each scanner accepts
at most ten Jobs. P4's separate 50-Job stress case uses the actual ten-Job host
plus query-only shards that share the **same** budget, not five allowances.
Native calls are not forcibly interrupted; an API returning after the deadline
invalidates the affected memory observation and is recorded as an overrun. The
50 ms p95 helper-tick acceptance target still requires measurement.

Job PID lists refresh at most once every two seconds. A fresh list is bracketed
by unchanged `TotalProcesses`/`ActiveProcesses` readings and must contain exactly
the active count without duplicates. NativeJob already bounds list-buffer retries
and size; the memory scanner refuses more than its remaining record budget before
opening members. Between lists, the same accounting stamp and every cached exact
process handle still alive and in the exact retained Job prove the cached set
complete. `TotalProcesses` is a lifetime count, so even a transient new child that
exits before the final count changes invalidates the cached proof. The scanner
does not use `TotalTerminatedProcesses` as an ordinary exit count.

Every memory query uses the original limited-right process handle, with exact
PID, creation FILETIME and logon identity. It validates the member before and
after its read and repeats the all-member liveness/membership check at the end:
an earlier process can exit during a later read, while its retained handle delays
the Job active-count change. Death, inaccessible identity, changed membership,
incomplete listing or exhausted budget makes the entire affected aggregate
unknown. It never publishes a partial sum or reopens a dead cached PID in the
same frame. Successful capture still describes a bounded observation, not a
promise that membership remains unchanged afterward.

An exact member appearing in multiple Jobs invalidates both aggregates, avoiding
nested-Job double subtraction. A stress coordinator must check the shared budget's
`invalid_execution_ids` **after all shards**; a later shard can invalidate an
earlier immutable receipt. No full-machine process enumeration is used.

## Private memory rather than shared working set

The native reader uses `K32GetProcessMemoryInfo` with
`PROCESS_MEMORY_COUNTERS_EX2`. `PrivateWorkingSetSize` is private resident RAM;
`PrivateUsage` is private Commit. Total working set is never substituted because
it includes shared pages. The current `JobFrame` contract validates the memory
pair together, so unavailable private working set also leaves its Commit
aggregate unknown; machine Commit sampling continues independently.

EX2 requires Windows 10/11 22H2 with the September 2023 cumulative update. The
reader requires a supported client x64 build/UBR, an own-process positive private
working-set probe using a borrowed pseudohandle, and complete output on each
query. It poisons the buffer, leaves `cb=0` as an output check, and requires the
full size, overwritten extension fields and `PrivateWorkingSetSize <= WorkingSetSize`.
An old API returning TRUE or zero-filled extension fields alone is insufficient.
An individual workload's private working set may legitimately be zero once the
capability probe succeeds. Unsupported or inaccessible EX2 yields unknown and
zero subtraction, not a total-RSS fallback.

Primary API references:

- [PROCESS_MEMORY_COUNTERS_EX2](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex2)
- [GetProcessMemoryInfo](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo)
- [Microsoft process-memory example](https://learn.microsoft.com/en-us/windows/win32/psapi/collecting-memory-usage-information-for-a-process)
- [Job basic accounting](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information)
- [Exact Job membership query](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob)

## Failure and ownership

`last_memory_scan` is a tuple of frozen `MemoryScanResult` values carrying the
execution ID, current capture ticks, reason, attempted count and accounting
stamp. No process list, command or provider output enters frames. Detailed reasons
such as `inaccessible_identity` and `member_scan_timeout` remain available to P4;
the public frame uses `memory_attribution_unavailable`. The source consumes a
receipt only once and suppresses it if the following Job CPU read sees a changed
accounting stamp. Failed memory collection leaves every Job CPU read and machine
CPU/Commit observation available. Existing overall work/skew checks can still
invalidate an over-budget frame.

The scanner owns cached process handles; the host owns borrowed Job handles.
Release closes cached processes without closing the Job. Failed close and
interrupted acquisition owners stay reachable. Known failed closes have bounded
explicit cleanup retry. Unknown native close outcomes are never reissued and
block reopening the PID; helper shutdown cannot claim clean cleanup while those
owners remain. This path changes no limits, exemptions, launch rights or runtime
mode and performs no Set, kill, trim, suspend or process spawning.
