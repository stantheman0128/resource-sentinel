# Disk-space incident, 2026-09-19

Read-only investigation. No file deletion, pagefile setting change, process control,
trace of user file contents, full-drive scan or notification send was performed.

## Verified event

The comparable change-tracker endpoints are 04:09:44 and 04:13:24 Asia/Taipei:
220 seconds, not one minute. C: used space increased 10,246,017,024 bytes
(9.542346954 GiB). The corresponding `changes.sqlite3` event is ID 8716 and is
explicitly `not_attributed`.

The old collector rounded this to 9.6 GiB and listed process write I/O:
T3 Code (Alpha) 266.7 MiB, MsMpEng 148.6 MiB, System 127.8 MiB. Their 543.1 MiB
sum is neither the allocation delta nor an attributable part of it. Process I/O
can include repeated overwrites and activity that does not consume new C: space.
It also lacks file names and complete coverage of short-lived processes.

`events.log` lines 586/587 repeat the loss at 04:11:56 and 04:13:24. A 04:12:15
collector timeout at coordinator cleanup occurred before saving the old disk
baseline, allowing the next collection to compare against it again. These records
must not be summed as two independent 9.6 GiB losses. The alert template also
hardcoded one minute instead of publishing the actual interval.

## Pagefile evidence and limits

| Measurement | Observation |
|---|---|
| Stored Commit limit, 04:09:44 | 83.55 GiB |
| Next successfully stored Commit limit, 04:14:18 | 84.56 GiB |
| Stored pagefile used, same two samples | 1.97 → 1.95 GiB; usage is not allocated file size |
| Pagefile logical length, read at 04:19–04:20 | 31,590,359,040 bytes (29.42081 GiB) |
| Pagefile last write time | 04:10:38.821361, inside the incident interval |
| WMI AllocatedBaseSize, current | 21,420 MiB (20.91797 GiB) |
| Native GetPerformanceInfo at 04:20:29 | Commit limit 90,791,383,040 bytes; physical total 68,330,749,952 bytes |
| Native limit minus physical total | 20.91809 GiB, consistent with WMI but below logical file size |
| Logical versus WMI difference | 8.50285 GiB; unresolved semantic/state difference |
| GetCompressedFileSizeW allocation query | ERROR_SHARING_VIOLATION (32); allocated size unavailable |
| Automatic pagefile management | Enabled; read-only observation |

This makes the pagefile a strong candidate, not a proven complete attribution.
There is no synchronized before/after native allocation measurement. The stored
Commit interval ends 54 seconds after the disk event. Neither the logical size
nor Commit-limit difference may be silently treated as exact allocated bytes or
deducted from the event as proven attribution.

Root file tracking was paused by machine load. Its monitored roots did not include
the relevant T3/pagefile scope and had no comparable current scans. The older
September 9–11 disk audit cannot establish the source of this September 19 delta.

Core database evidence was rechecked with normal `mode=ro` SQLite connections.
An initial sandbox-limited immutable read was not used as proof of current WAL
contents. Private DBs and complete logs remain local and are not in this commit.

## Required correction

Record exact free bytes, timestamps and baseline/event identities independently
of late collector completion. Distinguish same-window observed allocated growth,
logical file growth, WMI backing capacity, actual pagefile usage and process I/O.
Unknown allocation remains unknown. Alert retry state must distinguish pending,
attempted, acknowledged and ambiguous delivery; no exactly-once network promise.

Retrospective writer-to-file causality is not recoverable from existing counters.
Future per-file attribution would require a separately validated bounded file-I/O
trace; it must not be described as already implemented by these counter changes.
