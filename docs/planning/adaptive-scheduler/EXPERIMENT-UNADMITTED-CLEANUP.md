# Original unadmitted experiment cleanup

Status: contract before implementation, following `9657a32`. This completes the
local owner cleanup needed when an experiment is intentionally abandoned before
admission/native preparation. It is not permission to discard needed queued work
to gain capacity or finish a turn. Production adaptive remains off.

## Original authority

`Coordinator.abandon_experiment(demand)` accepts only the retained original
`DailyExperimentDemand` and actual daily Coordinator. Permanently seal further
admission and native preparation before the first cleanup acquisition. Reject
any original native preparation, completion/release operation, exported claim,
ordinary abandonment, unknown prepare result or unsettled submission guard.
Pending admission cleanup must first use the existing original settlement API.

Retain each returned admission POLICY guard on the experiment before its native
wait; ordinary successful admission currently clears the inner pending reference.
The retained tuple binds actual policy/store, guard, immutable binding and nonce.
This is evidence from the original attempt, never a guard adopted from current
SQL or a serialized result. A later admission attempt can replace it only after
positive cleanup of the preceding attempt. Cleanup captures the exact tuple,
original transaction and closed connection, original generation, demand/snapshot,
process witness, ledger/file and directory identity, caller process and thread.
Require exact Boolean native-exit/no-entry and nonce-clear facts. Unknown or
unreturned guard ownership cannot be reconstructed by this API.

## Bounded access and exact cancellation

Use a distinct concrete retained operation with READ and ABANDON phases only.
No new POLICY guard/native wait/readiness RPC or general capacity UDF is allowed.
Validate the full original ACTIVE/DRAINING generation, source/config/imports,
actual connection/file and original POLICY binding on every transaction. A
SEALED retirement cannot acquire new queue mutation authority.

Read bounded full experiment history and exact original queue/execution/request
obligations. Any admitted metadata, managed row, reservation, routed task,
descendant, archive, exclusion or completed experiment refuses this route.
QUEUED requires the full original managed queue binding. No row is sufficient
only for a context that never began submission, or an exact first transaction
positively rolled back before any COMMIT attempt and positively closed. Generic
ABSENT_AFTER_SUBMISSION is not cleanup evidence.

Under one BEGIN IMMEDIATE, freeze the complete original queue preimage before
deleting only that row. A fixed DELETE UDF and temporary full-row trigger must
validate the exact operation/connection/frame and preimage at execution time.
No reservation, archive, metadata, exclusion, receipt or other owner's row may
be written. No capacity is released because this path never owned an allocation.
Do not reuse the admitted experiment cleanup receipt schema for a queued intent.

Retain the original transaction and COMMIT-attempt flag before publication.
Lost acknowledgement may reconcile absence only for this exact original delete
attempt after positive SQL close. If the row remains, retry only the same full
preimage; a changed row refuses. A known never-COMMIT rollback can re-evaluate
the still-original queue. Unknown rollback/close retains the original connection
and forbids reopening. Never infer that another caller's absent row was deleted
by this operation unless its own COMMIT attempt exists.

## Positive final cleanup

After acknowledged/reconciled cancellation or positive never-submitted/rejected
proof, read back absence of all original obligations with positive SQL cleanup.
Then close only the original retained self witness. Known CloseHandle FALSE can
retry only that handle after readback; unknown close remains quarantined. A
positive close followed by interrupted local bookkeeping may finish on the same
owner without another native call. Clear only the original local credentials and
mark the original context closed. A completed replay is bounded read-only.

Return explicit QUEUED_CANCELLED, NOT_SUBMITTED or SUBMISSION_REJECTED with
`launch_authorized=false` and no reservation ID. Do not manufacture a native
completion, production FINISHED, a daily release receipt or new work authority.

## Verification boundary

Use real isolated SQLite admission/queue/transactions with synthetic native
owners for fault injection. Cover original-object substitution, full row/ledger/
generation binding, admitted and native-prepared refusal, lost COMMIT/close and
native close outcomes, repeated read-only completion, other-owner preservation,
readiness-free DRAINING cleanup and sealed-generation mutation refusal. Native
capability/recovery/overhead/A-B gates remain unverified by these tests.
