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
remainder is unread the tick reports unverified inventory. Other terminal states
(`CANCELLED_BEFORE_START`, `START_FAILED`) still count as live, because only
finalization carries a native proof. Enough unprovable history therefore ends in
`supervisor_inventory_bound_exceeded`, and the tick reports that as unverified
inventory.

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

`tests/test_adaptive_p3_flow.py` runs flow A to G on one isolated ledger with the
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
through the formal journal and sets the synthetic native flags. The control slot
is not exercised. None of this is evidence of Windows launch, containment,
crash, CPU effect or restore timing, and no such number is claimed.

Flow step H is not delivered. No production entry point lets a legitimate owner
take over lifecycle accounting after guardian death. The flow test pins the
current safe behavior: a replacement guardian identity is refused with
`guardian_custody_binding_mismatch`, it cannot reconcile the empty Job into
`FINISHED`, and the allocation stays held. That means a Job whose guardian died
keeps its allocation and its supervisor slot until the ownership transition
listed below exists.

Not red-verified: the new custody tests were not shown failing against the old
code by execution. That claim rests on reading the old code path.

Supervisor lock tests take a real exclusive file lock. The ledger is WAL, so a
plain `BEGIN EXCLUSIVE` does not block readers; the blocker uses
`PRAGMA locking_mode=EXCLUSIVE` and readers get a real `SQLITE_BUSY`.

## Contract clarification still required for all-witness loss

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
- Separate durable recovery ownership transfer, followed by lifecycle adoption,
  child accounting, original lease handling and full barrier/slot reconciliation.
- Retirement for `CANCELLED_BEFORE_START` and `START_FAILED` scopes, which need
  their own formal evidence before they can leave the concurrent bound.
- `GuardianLifecycle._job_scope` constructs its per-Job mutex without the custody
  handling now in `RecoveryOwner._job_mutex`. Not changed in this slice.
- Real continuous host capacity and loaded legacy-writer authority, native
  S1-S3 recovery, P4 observer/shadow costs, P5 canary and P6 paired A/B evidence.

All native-control and release gates remain unpassed. The daily runtime stays
unchanged and adaptive stays off; portable integration is evidence of source
behavior only.
