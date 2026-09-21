# Barrier clear for a finished Job, clarification C3

Status: a clarification adopted on 2026-09-22 by the repository owner's
instruction. It is not part of IMPLEMENTATION-PLAN.md and that file was not
edited. Nothing native has run, so everything below is source behaviour with
portable test evidence only.

## What plan 7.4 leaves open

Plan section 7.4 says a restore Query does not clear the admission barrier. The
barrier is cleared by compare-and-swap only after all own caps are restored,
accounting is reconciled and five fresh uncapped samples exist. Otherwise it
stays `RECOVERY_HOLD`.

The plan does not say whose samples those are when the controlled Job has
already ended. In the source this case has no exit:

1. `clear_locked` in `sentinel/adaptive/control_slot.py` needs a `RESTORED` row
   in `adaptive_actions` as the restore boundary. Only `GuardianControl` writes
   such rows. The orphan path, where the guardian is dead and the supervisor
   restores, writes none.
2. It needs uncapped samples of that execution taken after the boundary. A Job
   with no process produces no frame, and the supervisor has no sampler.
3. `clear_recovery_hold_locked` in `sentinel/adaptive/store.py` opens a
   `control_restore` evidence scope and revalidates the live allocation. Once
   `finalize_if_empty` has archived the allocation, that revalidation refuses.

`OrphanDrainOwner.drain` releases the slot and finalizes a natively empty Job,
and leaves the barrier at `RECOVERY_HOLD`. A guardian that finalizes a Job
before it collected five samples leaves the same state. While the barrier is
held, every new launch claim that is not exempt is refused, so one finished Job
blocks the logon until someone edits the ledger by hand.

Separate observation, not changed here: nothing in the repository calls
`GuardianControl.clear_admission_barrier` or `GuardianControl.observe_uncapped`
outside the tests, because no transport carries helper frames to the guardian.
The five sample path therefore has no production caller either.

## The owner's decision

The owner's answer on 2026-09-22: a Job confirmed empty by a live native query
counts as clearable, and the clear leaves an audit record.

## Why this keeps the plan's intent

The five samples exist because a capped Job uses less CPU than it wants, and
that drop must never be read as new capacity. The samples measure what the Job
really uses once the cap is gone, so admission reopens against real demand.

A Job that is natively empty and sealed has no demand left to measure. Its
allocation has been archived by `finalize_if_empty`, so no reservation is
waiting on a sample either. The other two conditions of 7.4 still hold and are
still proven: the cap is withdrawn and the accounting is reconciled.

## The evidence, all of it existing

No new flag or column states that a Job is finished. The new path accepts only
evidence the lifecycle already produces:

1. The execution row is `FINISHED`. Only `finalize_if_empty` writes that state,
   inside an evidence scope that showed zero active processes, an empty process
   list, a sealed launch, a disabled CPU control readback and a settled recovery
   manifest. That is the live native query the owner's answer refers to, and
   `FINISHED` is its durable record. A root exit, a lease expiry, a closed
   handle or mode off never writes it.
2. `LifecycleStore.assert_retained_terminal` passes for that row and the
   journal manifest. This is the check the supervisor inventory already uses to
   retire a scope. It requires a sealed top level row, no live allocation under
   that execution or reservation, and exactly one `managed_finished` archive
   whose fields match.
3. The journal manifest is settled: `original` is disabled, there is no pending
   intent, and `last_applied` is absent or disabled.
4. The control slot names this execution, is `RESTORED`, and matches the row's
   Job name, Job nonce, guardian epoch, logon and owner. The barrier is
   `RECOVERY_HOLD`. The POLICY scope is held and the registry revision is
   compared and swapped.

A row that reached `FINISHED` through its parent's cascade is refused, because
the native proof at that commit was about the parent's Job.

The orphan drain also reads the Job's membership on every pass. If a later pass
finds the row `FINISHED` and still reads a member in the Job, the two facts
contradict each other. That pass does not ask for the clear and reports
`finished_job_not_empty`.

`GuardianControl.clear_finished_admission_barrier` is the guardian side entry
for a Job the living guardian finished itself. Before it asks the store, it
reads the retained Job again and refuses with `finished_job_not_empty` or
`restore_unverified` when a member or a cap is present, and it reconciles the
manifest against the terminal archive. It has no production caller, for the
same reason the five sample path has none.

## What is written

One row in a new table `adaptive_barrier_clears`, in the same transaction as the
barrier change. It records the registry revision after the clear, the
execution, the slot id and slot revision, the guardian epoch, the reason
`finished_job`, the row's `finished_at` and the wall clock time of the clear.
The table is created on first use, the way `adaptive_actions` is. It records no
capacity and nothing reads it to make a decision.

As implemented, `registry_revision` is the primary key, so a replay at the same
revision cannot append a second record. The clear time is the caller's real wall
clock, taken once by `clear_recovery_hold_finished_locked`. Beyond the refusals
named above the table itself contributes three stable codes:
`control_barrier_clears_schema_unsupported` when an object of that name is not
the expected table, `control_barrier_clear_replayed` when the revision is already
recorded, and `control_barrier_clears_unavailable` for any other write failure.

## What does not change

1. `clear_locked` and `clear_recovery_hold_locked` are untouched. A Job that is
   still alive clears only through five fresh uncapped samples.
2. There is still no TTL, no force flag and no operator bypass. A missing piece
   of evidence refuses and the barrier stays.
3. The new path performs no Job operation. It sets no cap, ends no process and
   releases no allocation. `guardian_identity` and `guardian_epoch` in the
   manifest are read and never written.
4. The refusal reasons are stable codes, and a refusal found before the ledger
   is asked to change does not leave the POLICY entry nonce behind.

## Affected contracts

| Contract | Effect |
| --- | --- |
| Plan 7.4 barrier clear | One added way to satisfy it, only for a `FINISHED` execution |
| Plan 8.3 restore order | None. The clear happens after restore, release and finalize |
| Recovery owner is restore only | Kept. The supervisor side caller changes a ledger field and touches no Job |
| Guardian is the only normal actuator | Kept. No actuation is added |

## Known gap

A drain pass that finds the row already `FINISHED` offers the clear again, so a
refusal on one pass can clear on a later one while the same owner keeps custody.
If the supervisor process ends between the finalize commit and the barrier
clear, the next supervisor has no custody of that Job and does not retry the
clear. How a new supervisor treats scopes it holds no handle for is owner
decision 4 in the README, which was handed to Codex.
