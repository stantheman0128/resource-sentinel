# Proposed bounded resident-host telemetry contract

Status: implementation proposal for review, **not an implemented sink, measured
P4 result, changed gate or production activation**. Formal authority remains
`IMPLEMENTATION-PLAN.md` §5.5, §8, §11.2 and §12.1/S4. Existing capability
validation stays unchanged until this proposal and its evidence schema are
reviewed and implemented together.

## Observed production and evidence paths

| Owner | Current writer / sink | Persistence and failure behavior |
| --- | --- | --- |
| Helper | `helper_host.emit()`; `_report()` every `report_every_ticks` (default 30) | Serializes JSON, prints and flushes `sys.stderr`. No owned log path, retention, total-byte cap or rotation. Explicit test streams are supported. |
| Guardian | `guardian_host.emit()` after iterations/lifecycle changes | Prints/flushed stderr. Catches diagnostic sink errors so they do not unwind native custody. No rotation. |
| Supervisor | `supervisor_host.emit()` | Prints/flushed stderr; catches diagnostic errors. Native child creation supplies no explicit redirected standard handles and inherits no handles. |
| PowerShell entry | `scripts/adaptive-supervisor.ps1` | Invokes foreground Python. It does not create an adaptive telemetry file or impose retention. |
| Recovery | `RecoveryJournal(--journal-dir)` | Explicit canonical `<execution_id>.json`, durable recovery publication and original-owner checks. It forbids rotation of live evidence. This is a separate safety store. |
| Action/lifecycle audit | `LifecycleStore`, `adaptive_actions`, managed execution/owner state | SQLite safety/audit state. Its transaction and durability rules are independent of diagnostic output. |
| P4 producer | `NativeHelperHostSampler`, `read_runtime_footprint()` | Requires the original `sys.stderr` to be a writable UTF-8 regular file in isolated `session.log_directory`; verifies same file identity and measures actual report-file byte deltas. Footprint recursively counts all files in that directory and all noninternal SQLite rows. Raw producer traces live elsewhere. |

No resident-host production component currently owns the formal **20 MiB total /
7-day** adaptive aggregate/event policy. Redirecting stderr creates a file but
does not implement that policy. No proposed implementation may report this gap as
closed merely by discarding reports, excluding them from footprint, redirecting
to NUL, or lowering the test's report cadence.

Wrapper/workload stdio is a separate launch protocol. Preserve the actual
workload handles and wrapper launch-state output; this proposal does not route
workload output through the guardian or change the measured S2 topology.

## Minimum production implementation

Introduce one small shared `telemetry.py` component and narrow resident-host
bindings. No new process, control RPC, SQLite telemetry table or control
authority is needed. The three resident roles use one canonical sibling
directory, `<data-dir>/adaptive-telemetry`, with the same fixed policy; they do
not each receive 20 MiB. Recovery/audit locations must not be the telemetry
directory or its descendants, and the telemetry writer cannot accept arbitrary
deletion paths.

### Host-owned asynchronous interface

Proposed exact interface shape:

```python
sink = ResidentTelemetry(data_dir, role, identity, instance_id,
                         interrupt_clock=clock)
sink.start()
receipt = sink.offer(record, kind=TelemetryKind.AGGREGATE)  # or EVENT
status = sink.snapshot()
sink.request_stop()
```

`role` is one of helper, guardian or supervisor. Original native identity and
instance ID bind observations to the existing host; they are not supplied as a
logging authorization over JSON. `offer()` serializes the same sanitized record
and enqueues it without file I/O, external process spawning or waiting on a
cross-process lock. Enqueue, serializer and worker CPU/memory remain charged to
that host in P4. Neither `offer()` nor the worker can call a control or mutation
API. Nothing is emitted from inside POLICY/SQLite/mutation scopes.

Use one bounded worker thread per resident host, a bounded event queue and one
coalesced latest aggregate per role. The implementation constants (queue count,
serialized record bound, chunk bound and worker batch bound) are internal bounds,
not a second user policy or a tunable route around the 20 MiB cap. Proposed
starting bounds: 128 pending records, 16 KiB per record, 512 KiB chunks, at most
64 chunks/metadata files in the managed inventory. Aggregate records remain on
the existing 30-second helper cadence; unchanged per-iteration guardian and
supervisor status is coalesced into 30-second summaries. Actual errors,
restoration outcomes and lifecycle transitions remain events. Coalescing and
dropped-record counts are visible; they are not silently counted as persisted.

The worker uses ordinary buffered writes/flush, **no periodic fsync**. Required
first-intent/audit durability remains in the existing recovery journal/ledger.
Best-effort telemetry is never evidence that intent was durable, a cap was
applied/restored, a child exited or capacity was released.

### One shared quota and rotation owner at a time

A dedicated nonblocking cross-process file lock serializes inventory, eviction
and append. It is independent of POLICY, per-Job mutation locks and recovery
locks. No caller waits for it; a busy writer leaves bounded pending work for a
later batch. The implementation must use a local ordinary noninheritable lock
file, validate file/directory identity, reject symlinks/reparse points, and retain
uncertain file owners without retrying an ambiguous close. A failed lock never
means permission to write without accounting.

Within the lock, the writer:

1. Inventories only the fixed managed directory and the closed filename/schema
   set; bounded files and bytes only. Unknown files or partial/unreadable
   inventory cause refusal rather than deletion or a fabricated zero.
2. Expires aggregate/event chunks older than seven days using their recorded UTC
   capture range and real metadata. A backward/uncertain wall-clock jump may
   delay age deletion; it must not defeat the byte cap. Age uncertainty is
   reported and blocks a claim that the retention-age gate passed.
3. Reserves space for the complete pending serialized batch **before append**.
   Deletes the oldest eligible aggregate telemetry first, then the oldest event
   chunks if needed, keeping all adaptive telemetry plus its fixed metadata
   within **20 * 1024 * 1024 bytes**. No transient append-over-cap followed by
   cleanup is accepted.
4. Appends only complete bounded records to a compatible chunk or creates a new
   chunk exclusively. The writer opens/closes the chunk within this lock; it
   does not leave an active log handle that another process must unlink.
   Incomplete writes are detected and reported. No externally captured stderr
   file is truncated or silently replaced.
5. Publishes an in-memory receipt containing actual written/deleted bytes,
   created/retired chunk identities, current inventory bytes and outcome. A
   receipt never turns missing I/O evidence into success.

All directory paths are validated before any deletion, and only exact managed
chunk files are eligible. Do not recursively delete or move a directory. Do not
search the journal tree, SQLite/WAL, external evidence directory or workload
output. **All recovery manifests, including completed/conflicting ones, remain
outside this rotation**; this deliberately avoids inventing archival authority.

The worker cannot guarantee an OS file operation returns within a hard deadline.
Keeping I/O off the guardian/supervisor control thread prevents a blocked log
write from starving lease/recovery work. Worker memory and queues remain bounded
while blocked; overflow increments a counter instead of blocking producers.

### Failure, shutdown and existing stderr behavior

Disk full, read-only storage, lock contention, partial writes or failed rotation
produce explicit degraded telemetry state. They cannot throw into or delay the
restore path, skip Query verification, release capacity, discard recovery
manifests or authorize tightening. Existing required journal/DB write failures
continue to refuse new restrictive actions through their current contracts.
This proposal adds no exemption, durability bypass or alternative Set path.

Telemetry health is checked by the P4/promotion gate. A failed or dropped
required report prevents a claim of complete telemetry evidence. Diagnostic
failure does not masquerade as a successful storage gate. A separate decision to
make diagnostic degradation initiate a runtime drain would be an additional
control-policy change and is not silently included here.

Shutdown requests a bounded drain of pending diagnostics after control/lifecycle
cleanup. No success receipt claims all records persisted unless actual worker
completion confirms it. Pending telemetry/file-owner state and dropped counts
remain visible; no telemetry wait may hold a native control owner or delay
restore. Exact file-owner cleanup rules must be tested separately from control
custody; a logger's state cannot be used as proof of control cleanup.

Keep `emit(record, stream=explicit_stream)` for existing serializer tests and
one-shot diagnostics. Managed resident `emit()` routes to the installed sink;
it must not simultaneously duplicate every record to an unbounded redirected
stderr file. Before sink initialization, a bounded startup/refusal diagnostic can
still use stderr. Failure reporting must not recursively log to the same failing
sink. This changes the resident diagnostics interface and therefore requires the
P4 integration update below; it does not alter command stdio.

## Specific P4 deviation and proposed correction

Current `capability_evidence._p4()` requires:

```text
idle_after[name] <= idle_before[name]
for private_bytes, handles, rows, log_bytes
```

For logs, this is stronger than formal §11.2's bounded growth/retention contract.
A correct initially empty 20 MiB ring should grow while retaining fresh useful
reports and then rotate within the cap. One hour of genuine reports can increase
its size without a leak. Pre-filling it to make the after value flat, clearing it
before the after snapshot, suppressing reports or hiding its files would corrupt
the experiment. None is allowed.

Propose changing **only the log-byte comparison**, once the actual sink and its
new evidence verifier exist. Keep existing private-byte, handle and row
comparisons unchanged in this patch; any separate memory/row retention or noise
clarification needs independent evidence and review. Do not infer that bounded
log rotation permits deleting durable action/lifecycle history.

The replacement log gate must require all of:

- Original production sink instances on every resident role, pinned source and
  fixed 20 MiB/7-day policy. An arbitrary callback, JSON `bounded=true`, stderr
  adapter or postprocessed size claim is insufficient.
- Original host serializer/report calls, actual accepted/persisted sequence
  coverage and unchanged required cadence. All report work and logger threads
  are included in the measured monitoring cohort. Preserve the existing
  deduplication of exact process identities across supervisor/keeper/readiness
  roles; no additional CPU/private-memory allowance is introduced.
- Bounded native directory inventories before, during and after the run, plus
  every successful shared-lock append/rotation receipt. Observed and reserved
  bytes never exceed 20 MiB; seven-day expiration is verified where applicable.
  Missing inventory, clock uncertainty, write errors, overflow, unexplained
  file replacement or dropped required reports fail this evidence claim.
- Byte conservation: actual ending bytes equal starting bytes plus confirmed
  writes minus confirmed deletions (including explicitly accounted metadata).
  Incomplete writes are failures, not successful bytes. Rotation counters alone
  do not prove conservation; bind each changed file identity/size to the
  inventory and original writer receipts.
- Preserve/hash the recovery directory inventory and relevant ledger state
  across storage-fault/rotation tests. Live recovery manifests must be intact;
  disk-full logging cannot prevent an independently observed disabled Query in
  the existing isolated recovery fixture.
- No unbounded writer queue, retained stream/handle growth, chunk count growth or
  worker allocation. Existing one-hour idle/cohort measurements remain real.

If a short native run never reaches the rollover or age boundary, record those
branches as **not exercised natively**. Deterministic isolated filesystem tests
may use an explicit small quota/time fixture to verify boundary logic, but may
not call that a native 20 MiB/7-day measurement. Do not manufacture runtime log
prefill to satisfy the old comparison. Whether combined structural/boundary
tests plus genuine below-cap native observations satisfy promotion must be
stated in the reviewed acceptance contract, not inferred from a green result.

## P4 producer compatibility boundary

The current `helper_report_stream` identity and fstat-size-delta check cannot
silently continue after a queued/rotating sink is introduced. Replace it with an
original typed `helper_telemetry_sink` and authenticated observations of the
guardian/supervisor sinks from the actual fixture bridge. `NativeHelperHostSampler`
must prove the original sink/serializer/offer/worker bindings, then measure both
immediate report enqueue cost and background I/O in the process CPU totals.

The report tick retains an actual enqueue receipt; a later persisted receipt is
correlated by host instance and sequence. A queued record is not a written
record. The leak artifact must carry the full bounded-log evidence above while
preserving the raw historical `log_bytes` observations. Version the closed P4
schema/producer inventory together; old artifacts remain old evidence and are
not rewritten into the new contract.

The current aggregate bridge is separately incomplete. This proposal neither
replaces it nor makes its missing original host/process custody optional.

## Implementation and review slices

1. Add `telemetry.py` with isolated filesystem/concurrency/failure tests: exact
   shared cap, byte reservation, oldest-aggregate eviction, seven-day expiry,
   partial writes, full/read-only disk, nonblocking contention, reparse refusal,
   no recovery-directory traversal, bounded queues and uncertain cleanup.
2. Bind actual helper/guardian/supervisor diagnostics after the current frozen
   host changes are committed. Preserve recovery operation ordering and
   exception handling. Test original production startup, report, failure and
   cleanup behavior; keep adaptive mode off.
3. Update the P4 bridge/producer and closed evidence schema together. Keep the
   old strict comparison until the new original-sink evidence can be produced
   and verified. Document the exact log-only deviation and review it explicitly.
4. Run isolated native overhead/storage/recovery scenarios with all resident
   costs charged. Save genuine failures and unexercised branches. Do not promote
   on implementation tests, a contract document or bounded-policy constants.

No source, runtime setting, Scheduled Task, capability predicate or gate result
is changed by this proposal file.
