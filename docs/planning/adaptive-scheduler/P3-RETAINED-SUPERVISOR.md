# Resident supervisor and dead-guardian restore

2026-09-20. This implements recovery with a previously captured native witness.
P3 is incomplete; this is not a Scheduled Task installation, all-witness-loss
recovery, lifecycle ownership transfer or permission to activate adaptive mode.

## Connected implementation

`RecoveryOwner.capture()` duplicates the exact live guardian process handle and
pins the existing ledger POLICY binding while holding that same native mutex.
It creates no replacement policy namespace, does not infer death from a PID,
and does not accept serialized liveness/authority flags. After capture, restore
does not access SQLite. It waits for the retained guardian process object to be
signaled, holds the recovery-instance, POLICY and per-Job mutexes, verifies the
formal manifest and reopens the exact named Job with the existing native ACL and
nonce checks. It compares current control with original/last/pending values,
disables only an owned value, independently queries disabled and then settles
the journal. Immutable creator identity/epoch remains unchanged.

`GuardianSupervisor.attach()` connects that owner to an existing shared ledger.
Its bounded tick refreshes known Job scopes, distinguishes unavailable inventory
from a readable contradiction, observes the retained guardian and dispatches
restoration for each known scope after verified death. One Job's failure does
not strand the remaining known Jobs. DB outage permits cached-scope withdrawal
while explicitly reporting incomplete inventory. A readable identity/binding
contradiction remains sticky. No result releases allocations, exclusions or a
control slot, and native restoration is not presented as complete accounting.

Normal `PolicyCoordinator.hold()` now revalidates the actual binding and entry
nonce after acquiring the native mutex and before exposing its guard. The new
read has a 250 ms SQLite busy timeout. A prepared waiter whose authority changed
while it was waiting cannot enter a native consumer with a stale guard.

## Custody on constructor and capture failure

A failed `NativePolicyMutex` constructor used to drop what it had allocated. If
closing the new handle failed, nothing referenced the object afterwards, and the
sanitizing conversion to `policy_mutex_identity_unavailable` discarded both the
retained identity duplicate and the cleanup notes. `windows.py` now keeps the
partial object on the raised error as `_policy_mutex_cleanup` and carries
`_identity_handle_cleanup` and every note across the conversion. This is the one
change outside the supervisor files, because the custody was lost before
`RecoveryOwner` could see it.

`RecoveryOwner` treats a per-Job mutex constructor failure in three ways. A
clean native failure with no notes and no retained owner allocated nothing, so a
later pass may construct again. A failure that left owners is sticky until each
owner closes positively, and only then is one replacement built. Any other
failure is sticky with the original error, so a retry loop cannot allocate an
unbounded series of mutexes. `close()` after a failed capture settles the owners
held only by the capture error, or refuses with `recovery_custody_unsettled`.

A follow-up pass closed four holes in that custody. When a raw handle or a
security descriptor failed to release inside `windows.py`, the error kept a note
but nothing that could try again. `_retain_native` now puts a small owner on the
error, which retries the release and drops its value only after the release
succeeds. The helpers that read and settle those owners moved into `windows.py`
as `retained_owners`, `settle_retained`, `replacement_allowed` and
`unresolved_construction`, so the recovery owner and the guardian use one
definition. `RecoveryOwner.close()` refuses a capture error whose cleanup note
has no owner behind it, because a note alone cannot be settled. `close_verified`
clears each handle as it closes, so a retry after a failed mutex close does not
close the Job a second time. `GuardianLifecycle` builds its per-Job mutex through
the same three-way rule and refuses with `guardian_job_mutex_unverified` while
the first outcome is unknown.

Three limits remain. An entry whose Job open failed keeps `close_verified`
refusing, and no path settles owners carried on that open error. The guardian's
pending execution has no field for a mutex failure, so its stickiness lasts one
attempt. The branch that lets a clean native failure construct again cannot be
reached from a guardian entry point, because the fence failure poisons the
restorer first.

## Concurrent bound and retirement

The supervisor bound is now ten unretired scopes, not ten rows per cohort. A
scope retires only on existing formal evidence. `finalize_if_empty` is the only
writer of `FINISHED`, and it commits under the guardian's POLICY and Job fences
with a native proof that the Job is empty, sealed, CPU disabled and the manifest
settled. `_prove_retired` rechecks the ledger half through
`assert_retained_terminal`, which requires a sealed row, no active allocation,
exactly one `managed_finished` archive and a row bound to the manifest. The
journal half is the settled manifest. No new column or flag was added. SQL `FINISHED`
alone, a missing allocation or a missing Job name retires nothing: the scope
stays an obligation, keeps its slot and is still restored after guardian death.
A held obligation is asked again on every tick, at most ten proofs, so evidence
that completes later still frees the slot and lets `close()` succeed.

History is read once in `rowid` order, sixteen proofs per tick. While a
remainder is unread the tick reports unverified inventory. A named scope in
`CANCELLED_BEFORE_START` or `START_FAILED` still counts as live. The store would
write either state only under a never-started proof, but no production path can
reach that today. The one production cancel, in `admission.py`, accepts only a
row with no Job name, and the supervisor never lists such a row.
`mark_start_failed` has no caller, and neither guardian evidence provider
answers `cancel` or `start_failed`. A retirement check for those two states
would therefore verify evidence nothing can produce, so none was added. Enough
unprovable history ends in `supervisor_inventory_bound_exceeded`, and the tick
reports that as unverified inventory.

Unavailable and contradictory inventory are separated by the primary SQLite
result code (`BUSY`, `LOCKED`, `IOERR` and similar), two journal read reasons
and an unusable registry path. The store's own read transaction reports a lock
or an interrupt as `coverage_database_busy` or `coverage_read_timeout`, and both
count as unavailable. An independent review found the first version missed them:
a lock during a retirement proof became a sticky contradiction and stopped
restore for good. `SQLITE_ERROR`, such as a missing table, is a
readable contradiction and is sticky. An untyped `OperationalError` is not
accepted as unavailability. An error that still owns a journal cleanup handle is
sticky as well.

## Evidence

2026-09-20, this host, Python 3.13, through `scripts/invoke-sentinel.ps1`
(`-Priority P2 -CpuUnits 1 -RamGiB 1`). All 65 `tests/test_adaptive_*.py`
modules were named explicitly: 1515 tests, 0 failures, 0 errors, 0 skips,
183.8 s. The supervisor and flow modules alone: 29 tests, 15.2 s. A separate
review pass reproduced the earlier 1513-test run, then refuted the first
unavailability classification and showed a held terminal scope could never
retire. Both are fixed above, each with a test.

A later run the same day, after the custody follow-ups and the P4 to P6 tooling
landed, named all 70 modules the same way: 1629 tests, 0 failures, 0 errors,
0 skips, 190.1 s. The added modules are portable or read-only. None of them sets
a CPU control, and none is native evidence for a P4, P5 or P6 gate.

A third run the same day, after the orphan drain and the guardian control
consumer, named all 72 modules: 1700 tests, 0 failures, 0 errors, 0 skips,
178.5 s. Every Job, process and mutex in the added tests is a synthetic
in-process fixture, so this run is not native evidence either.

`tests/test_adaptive_p3_flow.py` runs flow A to H on one isolated ledger with the
production consumers: `Coordinator.admit_managed`, `ManagedAdmission`,
`GuardianLaunchOwner`, its `GuardianLifecycle`, the formal `RecoveryJournal`,
`PolicyCoordinator.hold` and `GuardianSupervisor.attach` with the real
`RecoveryOwner`. It asserts that root exit with a living child reaches
`DRAINING` with the allocation unchanged, that a living guardian gives no
restore authority, that recovery takes the recovery-instance, POLICY and the
same per-Job fence names the guardian used, in that order, that the only native
write is one `disable` followed by a fresh query, that the manifest creator
identity and epoch are unchanged, and that five ledger tables are identical
before and after restore.

Four parts are synthetic and labelled in the module. The kernel namespace of
mutexes, named Jobs and process handles is a fixture, and so is the wrapper's
process creation. One test process plays both roles, so the supervisor PID is a
fixture value patched into `recovery_owner` only. The cap is the fourth. No production
tightening path exists yet, so a labelled fixture publishes a pending intent
through the formal journal and sets the synthetic native flags. The same fixture
takes the control slot through the formal `begin_control_slot_locked`, with a
fixture evidence provider and a fixture mode value, because production supplies
no `control_begin` evidence and no mode switch. None of this is evidence of Windows launch, containment,
crash, CPU effect or restore timing, and no such number is claimed.

## Flow step H: the orphan drain

Step H is delivered as a restore-only drain. `sentinel/adaptive/orphan_lifecycle.py`
adds `OrphanDrainOwner`. It lives in the supervisor process and is built from the
`RecoveryOwner` that already holds the exact guardian handle, the reopened Job,
the settled manifest and the immutable creator epoch. It installs itself as the
ledger `evidence_provider` for `control_restore` and `finalize` only, and refuses
every other operation with `orphan_evidence_operation_unsupported`. Each pass
re-verifies guardian death, re-reads the manifest, re-queries native CPU control
and re-reads Job accounting inside the recovery-instance, POLICY and per-Job
fences, then releases the control slot through `release_control_slot_locked` and
finishes the scope through `finalize_if_empty`. `GuardianSupervisor.tick()` runs
that pass for every scope whose restore settled in the same tick and reports
`slot_released_executions`, `finalized_executions` and
`drain_unresolved_executions`.

Nothing is released early. While the Job still holds a process the drain returns
without touching the ledger, so the slot stays `HELD`, the barrier stays
`CONTROLLING` and the allocation stays live. A root exit, a lease expiry, a
withdrawn cap or a closed handle is never read as an empty Job. The drain owner
is not a guardian. It has no begin, tighten, heartbeat, launch or adopt
operation, it never writes `guardian_identity` or `guardian_epoch`, and a
replacement guardian identity is still refused with
`guardian_custody_binding_mismatch`.

The POLICY level is taken once, by the store's own `PolicyCoordinator`, and
`RecoveryOwner._scope` accepts it through a new `policy_scope` argument. The
design direction for this slice assumed a Windows mutex is reentrant for one
thread, so the drain could nest its own POLICY acquisition inside the recovery
owner's. That is wrong here. `NativePolicyMutex._wait` refuses a second
acquisition of one name on one thread with `policy_mutex_recursive_entry`,
through a process-global name set, so the two handles cannot both be held.
Delegating the level keeps the documented order of recovery-instance, POLICY,
per-Job and then one short transaction, and no fence was relaxed to fit.

What step H still does not do. It does not clear the admission barrier: after a
drain the barrier is `RECOVERY_HOLD` and never `NONE`, and the five fresh
uncapped samples a clear needs belong to a separate owner. It does not know the
root exit code, so it never calls `mark_root_exited` and invents no substitute;
`finalize_if_empty` does not ask for that code. It carries no native evidence.
Every backend in these tests is synthetic, and the native tests stay blocked on
this host by `require_supported_host()`, which refuses a foreign parent Job.

One inventory rule changed with the drain. `release_control_slot_locked` leaves
the slot row as the durable `RESTORED` boundary, and `_read_inventory` used to
refuse any slot whose execution was no longer live, with
`supervisor_inventory_slot_unknown`. That refusal is sticky. Once the first slot
holding scope finished, by this drain or by a living guardian, the supervisor
stopped restoring every other scope. The check now accepts one case: a slot in
state `RESTORED` whose execution has a `FINISHED` ledger row. That row owes no
cap, because `finalize_if_empty` commits only on a native CPU disabled proof. A
`HELD` slot, a malformed slot, or a `RESTORED` slot that names an unknown
execution outside the live set is still refused, and the flow test asserts both
refusals. After the drain the scope retires on the next tick and `close()`
succeeds while the barrier stays `RECOVERY_HOLD`.

`tick()` takes an optional `now`, used only as the `finished_at` a drain
records. The retirement proof compares `finished_at` with the archived
`started_at`, so a ledger seeded on a fixture clock needs the same clock at the
finish. A production host passes nothing and the store uses wall time.

`accounting.py` refuses every non-exempt admission while the barrier is not
`NONE`. A guardian that dies holding the slot therefore still blocks new
non-exempt work on the host after the drain, because `RECOVERY_HOLD` blocks
exactly as `CONTROLLING` does. The drain closes the accounting side, not the
admission side. The barrier clear has to exist before any canary.

Step H evidence, 2026-09-20, this host, through `scripts/invoke-sentinel.ps1`
(`-Priority P2 -CpuUnits 1 -RamGiB 1`). Four modules were named:
`tests/test_adaptive_orphan_lifecycle.py` (new, eleven cases),
`tests/test_adaptive_p3_flow.py`, `tests/test_adaptive_supervisor.py` and
`tests/test_adaptive_recovery_owner.py`. Red first, with `_drain_scopes`
disabled in `tick()`: `run 69 failures 2 errors 0 skipped 0`, the two failures
being the new step H test and the extended step F fence assertion. With the
production call restored: `run 69 failures 0 errors 0 skipped 0`, 27.1 s. The
eleven new cases pass in both runs because they drive `OrphanDrainOwner`
directly, which is the point of keeping the flow test as the production path
check. A review pass then added the inventory rule above, its two refusal tests
and one assertion that a ledger rejection keeps the POLICY entry nonce. The
first rerun failed one test, `run 71 failures 1 errors 0 skipped 0`: the
finished scope did not retire because the drain stamped wall time on a ledger
seeded with a fixture clock. With `tick(now=...)` the same four modules gave
`run 71 failures 0 errors 0 skipped 0`. The earlier custody tests are still not
red-verified by execution. That claim rests on reading the old code path.

A separate read-and-run verification pass then reran the drain, flow, supervisor
and guardian control modules: `run 77 failures 0 errors 0 skipped 0`. It found no
counterexample to the five drain claims. It also probed a case no repository test
covers: a slot whose `execution_id` is not a UUID after a completed drain gives
`supervisor_inventory_slot_unknown`, and `close()` refuses with
`supervisor_custody_unsettled`. The pass ran single threaded on synthetic
backends, so it says nothing about a real race or a native Job.

Supervisor lock tests take a real exclusive file lock. The ledger is WAL, so a
plain `BEGIN EXCLUSIVE` does not block readers; the blocker uses
`PRAGMA locking_mode=EXCLUSIVE` and readers get a real `SQLITE_BUSY`.

## Contract clarification for all-witness loss

Decided by the user on 2026-09-20: §8.3 is narrowed and §3.2 stays as written. A
fresh process that never held the old guardian's handle reports the guardian as
UNKNOWN, tells the user and performs no restore. The supported route is the one
built here: the supervisor attaches while the guardian is alive and keeps the
handle. This matches the last row of the §9 fault matrix, which promises an
independent supervisor or a manual restore when every recovery owner is lost,
and no automatic settlement. No weaker death evidence is accepted, so the PID
and creation-time inference below is recorded as considered and rejected. Two
existing cases pin this behavior:
`test_capture_requires_alive_witness_and_retains_failed_capture_owners` and
`test_alive_and_unknown_guardian_do_not_open_or_control_job`. The background
that led to the decision follows.

Formal plan §3.2 requires the old guardian's held process handle to be signaled.
§8.3 also describes a fresh Scheduled Task recovery after helper, guardian and
wrapper have all disappeared. These requirements are not automatically
compatible when the last old-process reference is gone. The recovery manifest
has immutable creator identity and integrity checks, but no retained kernel
process object and no standalone durable POLICY-instance provenance.

Windows process handles remain valid after termination until closed. Retaining
the actual handle therefore satisfies the existing death contract; this slice
uses that route. See Microsoft's [process-handle contract](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers).

Microsoft explains that a PID cannot be reused while its old process object
still exists. A successfully opened same PID with a positively queried different
creation FILETIME could therefore support an inference that the original
incarnation ended. It is not the held-handle-signaled proof currently required,
and has not been added as takeover authority. See [PID lifetime](https://devblogs.microsoft.com/oldnewthing/20110107-00/?p=11803).

The formal [OpenProcess documentation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)
does not provide a complete general contract equating any nonzero-PID error 87
with verified death; it explicitly documents that error for PID zero. Missing,
inaccessible or mismatched identities therefore remain UNKNOWN. No global
identity rule or safety invariant is weakened to manufacture a cold-recovery
pass. Promotion remains stopped for this unresolved all-witness-loss contract.

## Remaining integration gates

- Actual independent service host/startup and supervisor scheduling, outside the
  collector kill subtree. No task or global startup entry was installed.
- Durable instance provenance for a new process with no captured POLICY binding,
  and an accepted exact-death contract when every native witness is gone.
- Clearing the admission barrier for a Job that has already finished. The
  guardian can clear `RECOVERY_HOLD` for a live Job with fresh uncapped samples;
  see P3-GUARDIAN-CONTROL.md. A Job finished by the orphan drain produces no
  samples, so its barrier stays, and plan 7.4 needs an owner decision first.
- Separate durable recovery ownership transfer for a scope that must keep
  running, followed by lifecycle adoption, child accounting and original lease
  handling. The drain finishes a scope; it does not adopt one.
- Guardian evidence for `cancel` and `start_failed` on a named Job. Without it a
  prepared Job whose launch positively failed before user code keeps its
  allocation and its supervisor slot. Retirement of those two states follows
  that evidence and is not built ahead of it.
- Real continuous host capacity and loaded legacy-writer authority, native
  S1-S3 recovery, P4 observer/shadow costs, P5 canary and P6 paired A/B evidence.

All native-control and release gates remain unpassed. The daily runtime stays
unchanged and adaptive stays off; portable integration is evidence of source
behavior only.
