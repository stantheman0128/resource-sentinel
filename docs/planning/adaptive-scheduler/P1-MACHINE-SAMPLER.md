# Read-only machine sampler: implementation and native evidence

2026-09-20. This is a prerequisite for the S1 recovery consumer. It does not
complete P1's Job capability gates, P3's guardian, or P4's helper/overhead gate.
No production runtime, configuration, Scheduled Task or startup entry changed.

## Actual implementation

`sentinel/adaptive/machine_sampler.py` performs a fixed number of read-only
Windows calls per explicit `sample()`. It has no worker loop, process scan, Job
API, persistence or control writer. `GetSystemTimes` supplies the cumulative
machine CPU counters; `GetPerformanceInfo` supplies physical and Commit page
counts, multiplied by its measured PageSize. Kernel time already includes idle.
CPU busy units are the non-idle fraction times the logical processor count.

The first endpoint preserves real memory values but reports unknown CPU. A
subsequent CPU window is valid only if the entire possible interval between
capture brackets lies within 0.5–1.5 seconds, the capture costs at most 100 ms,
and counters/topology remain valid. The supported denominator is one processor
group with 1–64 logical processors. Missing topology does not invent a machine
frame; missing counters do not become zero usage. Freshness dates from the
oldest read in the endpoint, with a three-second limit.

Backwards counters, invalid windows, changed topology and read failures discard
the previous pair. Runtime epochs identify this sampler's continuity, not an OS
boot or an earlier process. An observed suspend/resume must invalidate the
clock explicitly; these counters alone cannot exclude a short sleep.

## Real failure found and repaired

The initial clean candidate `307927ef783a731de95b17fd9448372415714aab`
passed all 27 portable tests but failed both explicitly selected Windows smoke
tests. A native query returned `telemetry_stale:machine_native_api`.

Read-only diagnosis showed that this host's `kernel32.dll` does not directly
export `QueryInterruptTimePrecise`. The same API resolves through the official
`api-ms-win-core-realtime-l1-1-1.dll` contract. Both the new sampler and the
existing S1/S3 test clock now use that API-set entry. The API, 100-nanosecond units
and sleep-inclusive interrupt-time domain are unchanged; there is no fallback
to wall time or a less precise clock. See Microsoft's
[API-set listing](https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis)
and [clock contract](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise).
The failure was an incorrect DLL binding, not proof of unsupported Windows Job
control. The regression fixture includes a kernel DLL without that forwarder.

## Verification

Windows x64, Python 3.13. Each test candidate was exported from the exact Git
index tree, excluding the protected incoming working-tree overlay. Execution
used the ordinary daily Sentinel wrapper at P2, CPU 1, RAM 1 GiB, I/O 0.

Final source/test tree `9d22946a414d4a4417b5f11f801acda022992435`:
**70 passed, 0 failed/errors/skipped**, 1.507 seconds. This includes 28 portable
sampler cases, 40 existing identity/recovery/stage-gate cases and two real
Windows read-only tests. The latter validate an initial native endpoint and an
actual one-second CPU pair, including the recovery consumer's real clock.
Neither test retries an invalid native window to hide failure.

```text
python -m unittest tests.test_adaptive_machine_sampler tests.test_adaptive_machine_sampler.NativeMachineSnapshotSmoke.native_snapshot tests.test_adaptive_machine_sampler.NativeMachineSnapshotSmoke.native_window tests.test_adaptive_created_identity tests.test_adaptive_recovery_timing tests.test_adaptive_s1_gate
```

The native smoke methods are explicit-only; default unit discovery does not
silently run them or count a platform skip as capability evidence. Native Job
spike opt-in remained zero. No test Job, process workload, CPU cap or test
Scheduled Task was created. Private logs retain both the failing candidate and
the corrected run; only the necessary results are published here.

## Remaining gates

Machine sampling alone supplies neither precise Job attribution nor full
FastFrame authority. Its capture time is not whole-helper overhead. The next
consumer must retain exact Job/journal ownership, verify disabled controls,
reconcile the shared accounting, and accept five fresh uncapped windows before
the final recovery-barrier CAS. Suspend/resume notification handling, complete
runtime cohort handoff and actual native control/recovery tests remain separate
requirements. P1/P3–P6 must not be promoted on this evidence alone.
