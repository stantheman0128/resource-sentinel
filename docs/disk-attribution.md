# Disk-space attribution and alert evidence

This change is prepared in the isolated adaptive implementation checkout. It does
not deploy the collector, change production configuration, or enable adaptive
control. The incident findings are in
[disk-space-incident-20260919.md](work/disk-space-incident-20260919.md).

## What a disk alert establishes

The collector compares exact `Win32_LogicalDisk.FreeSpace` bytes for the same drive
and volume serial at two recorded sample endpoints. The elapsed interval is the
actual timestamp difference, not the configured scheduling period. `GiB` and
`MiB` labels match the existing binary units. A SHA-256 event ID binds the volume,
endpoint timestamps, and exact byte values.

The old notification called process write-I/O rankings suspects. That conclusion
was unsupported: those counters contain transfers rather than newly allocated
volume space, do not name files or volumes, and miss exited processes. They are
now explicitly **I/O correlation**, retain their own process-sample endpoints,
and are never deducted from disk-space loss. File writer attribution remains
`unavailable`. The alert no longer suggests cleanup without identifying data.

## Bounded pagefile observations

The existing WMI pagefile list supplies at most 16 paths to a separate read-only
metadata probe. Its parent-process wait budget is 3 seconds. Failure leaves an
explicit unavailable measurement; it does not block admission or change Windows
pagefile management. No file contents, recursive directory scan, persistent trace,
or workload process control is used.

The existing bounded-query helper terminates the direct probe process on timeout.
It does not establish that a compiler child created by PowerShell Add-Type has
also exited. Cold-start cost and timeout child cleanup remain unverified; the
three-second budget is not a proven process-subtree lifetime bound.

For each path the probe records these separate fields:

| Field | Meaning and failure behavior |
| --- | --- |
| `allocation_bytes` | Native `FileStandardInfo.AllocationSize`; null when the metadata handle or query fails. |
| `logical_bytes` | `FileStandardInfo.EndOfFile`, with ordinary file metadata length as a fallback. Never treated as allocation. |
| `native_storage_bytes` | Independent `GetCompressedFileSizeW` result. Its uncompressed-file semantics can differ from cluster-rounded allocation, so it is not used as an allocation fallback. |
| `wmi_allocated_bytes` | Existing `Win32_PageFileUsage.AllocatedBaseSize` converted from MiB. Kept as a provider observation, not substituted for current native allocation. |
| `wmi_used_bytes` | Existing WMI pagefile usage. Used space is not the reserved file allocation. |
| Native error codes | Sharing violation, access denied, missing file, and other failures remain explicit; a failed measurement never becomes zero. |

The metadata handle requests access 0 and read/write/delete sharing. Windows can
still deny a live system pagefile. A successful ordinary test file probe therefore
does not establish that live pagefile allocation is readable on this host.

Only matching pagefile paths with successful native allocation measurements in
both **the same two disk sample windows** contribute a delta. Each endpoint's
window, from pagefile enumeration start through the separately bracketed disk
query and native metadata completion, must be no more than 5 seconds and contain
its per-file timestamps. Slow WMI queries therefore downgrade coverage as well.
These are sequential observations, not an atomic filesystem snapshot. The full
aggregate is unknown if enumeration fails, membership changes, an endpoint falls
outside its window, or any native allocation is unavailable. The signed partial
sum is retained separately without being presented as complete attribution.

When coverage is `complete_pagefiles_only`, the signed residual is:

`unexplained_net_allocation_bytes = -volume_free_delta - pagefile_allocation_delta`

That residual can be negative when other files are freed during pagefile growth,
or larger than the observed loss when pagefiles shrink while other allocations
grow. It is evidence of a remaining net balance, not a culprit identification.
For incomplete coverage the exact residual is null and the complete volume loss
remains unverified. WMI values, logical size, Commit-limit changes, and process I/O
are never silently used to fill the gap.

Microsoft references:
[FileStandardInfo](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_standard_info),
[GetCompressedFileSizeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew),
[Win32_Process](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process).

## Checkpoint and delivery recovery

`disk-attribution-state.json` is a separate disk checkpoint. A flushed temporary
file replaces the existing file using `File.Replace`; `Move-Item -Force` is not
used because its overwrite path can first delete the prior destination.
The collector writes the new baseline and event outbox immediately after the disk
probe, before later optional collection stages and notification requests. A later
timeout cannot make the next run recount the old baseline as a new event. Legacy
`state.json` remains available to existing CPU/I/O/resource-policy consumers;
rounded legacy drive values are not imported as exact disk evidence.
An existing unreadable, malformed, oversized, or unsupported checkpoint is
preserved and reported unavailable. That run skips disk attribution/delivery
while the rest of resource collection can continue; it never resets the outbox
or cooldowns to manufacture a clean start.

The existing single-collector ownership remains required. This sidecar is not a
multi-writer database. The outbox retains 64 events, with explicit eviction counts;
longer history is in `events.log`. The per-drive 30-minute notification cooldown
is retained independently of outbox eviction.

Delivery states are explicit:

- `pending`: evidence persisted, no network attempt started.
- `attempting`: persisted **before** the request starts.
- `sent`: Telegram returned `ok=true`; the acknowledgement timestamp is saved.
- `unknown_delivery`: timeout, unsuccessful response, or recovery after an
  interrupted attempt. No automatic resend of this event.
- `suppressed_cooldown` / `expired`: retained evidence, not a successful send.

The append-only event ledger has its own `pending`, `attempting`, `written`, and
`unknown_write` states. It is not replayed after an ambiguous append; the sidecar
still contains the full event. Ledger and notification state are separate from
collection scheduling. There is no exactly-once claim across network delivery,
process termination, or power loss. A failed save before a network attempt stops
that attempt rather than sending without a durable dedup record.

## Verification and limits

Run through the normal shared admission wrapper, in this isolated checkout:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_disk_attribution.ps1
```

The fixture suite verifies a 220-second / 10,246,017,024-byte loss, exclusion of
I/O and WMI from allocation arithmetic, incomplete/mismatched windows, pagefile
decreases and offsetting frees, volume identity changes, early-checkpoint replay,
ambiguous delivery and cooldown recovery, and native metadata on test-created
files only. It does not send notifications, run the collector, inspect live
pagefiles, or touch production state.

Existing counters cannot reconstruct historical writer-to-file causality. A
future incident-triggered ETW file-I/O trace could add PID/start identity, file
path, operation type and time correlations, but requires separate bounded
duration/output/privacy/privilege validation and matching filesystem allocation
evidence. Such a trace is not implemented here, and continuous ETW/USN scanning
is not part of this change.

Validation on Windows PowerShell 5.1, 2026-09-19: the isolated fixture suite passed
at 05:32 after two real regressions were corrected: explicit Int64 Math.Max for
multi-GiB deltas, and `[NullString]::Value` for File.Replace's optional backup path
(ordinary `$null` was converted to an invalid empty string). The prior failure
logs are retained locally. Native allocation metadata was verified on a test
file only. The production collector has not been replaced or run with this patch.
