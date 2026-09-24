# Original-owner successor after positive daily retirement

Implementation contract, 2026-09-24. This defines the remaining restart work in
DAILY-GENERATION-RETIREMENT.md; publishing it does not close that gap. It authorizes no daily installation, activation,
configuration change or native experiment during source implementation.

## Authority and scope

A successor may be requested only in the still-live process and original thread
that retains the exact, positively completed DailyRetirementOperation and its
predecessor DailyActivationHost. Preserve that host's owner, store, supervisor,
readiness objects and retirement operation. Never reset the old host for reuse.
A SEALED row, a JSON receipt, a dead PID, feature off, elapsed time or reopening
a process handle cannot reconstruct this authority. Generic activation and
SupervisorStartup cold-adoption refusals remain unchanged.

The predecessor must have completed its original freeze and seal POLICY
operations, all SQL cleanup, supervisor drain and close, readiness thread join,
listener/registry cleanup, cohort close and current-process handle close. Any
unknown acquisition, rollback, commit, nonce clear, guard exit or close holds
the original operation. Persisted SEALED describes only the ledger boundary;
it is insufficient proof of these later native outcomes.

Retain the exact original seal inventory snapshot and its digest before the
seal mutation. It remains bound to that capture's store, journal, seal guard,
process, thread and directory identities. Ordinary inventory validation must
not silently accept a different guard or phase. A successor-specific read-only
check may inspect this retained preimage only through the completed original
retirement operation. The snapshot/digest by itself grants no native, SQL,
admission or restart authority.

The fresh owner uses the current base interpreter and a new original current
process witness, RetainedCohort, generation UUID and readiness instance. Keep
the same canonical source manifest, fixed policy digest and ledger file
identity; this route is not a source upgrade. A source upgrade still requires
its separately reviewed installation path. Do not infer that another live
interpreter is safe merely because it may have the same source. Preserve the
existing cohort observations and wait for its original retirement conditions.

## Atomic transfer and immutable history

Use a retained successor operation with a preminted transition ID, fresh owner
and exact existing POLICY binding. Register all partial owners before their
effect boundaries. Its special connection scope permits only the reviewed
generation/history/fence/nonce metadata transition. It grants no reservation,
worker-capacity, queue, exemption, managed-launch or control mutation, and no
general daily-generation capacity UDF. Other consumers remain fenced.

Prepare bounded predecessor ledger/journal evidence before the final short
transaction. Under original POLICY, verify the retained retirement proof,
source/configuration/ledger identity, exact SEALED preimage, all existing
terminal/experiment receipts, current empty allocations/infrastructure and
restored control state. Preserve unrelated queued work and every lifecycle,
exemption, launch, experiment and control-history row. Do not delete terminal
rows or journal files to satisfy the ordinary cold-start empty check.

One transaction archives the complete predecessor generation and retirement
binding/seal, the retained inventory digest, successor binding and exact
transition/POLICY identity, and replaces the live generation/fence state. The
archive is immutable and independently schema- and digest-validated. All new
schema and payloads enter the existing bounded inventory accounting (4096-row
history and 16 MiB aggregate limits); exceeding a bound refuses, never prunes.
Removing the predecessor's live freeze is permitted only inside this exact
original transition after its history is retained. Generation guards continue
to reject stale prepared connections and all old-generation consumers.

No intermediate state is admission-ready. A committed successor row alone is
not readiness. Require original transaction completion, original connection
close, original POLICY native exit and exact nonce cleanup, followed by an
independent bound readback. Lost ACK reconciliation may inspect only the same
operation's exact preimage/postimage; it cannot remint a generation, adopt a
different nonce, reconstruct a guard or discard an unknown SQL owner.

## Fresh readiness and supervisor

Only the positively acknowledged fresh owner starts a new authenticated
readiness listener. Keep the predecessor listener closed; never reuse its
instance ID or handle. Admission resumes through the existing capacity checks,
58 GiB machine budget, physical/Commit reserves and unchanged exemption cap.
This operation neither grants nor revokes an exemption or enables CPU control.

Start a fresh supervisor through a successor-specific complete history check.
The same proof must be revalidated both at initial startup and adjacent to the
first guardian Create boundary. The generic cold-start path remains refusing;
no flag or public status dictionary substitutes for original retirement and
complete retained history. Preserve off mode and every normal launch boundary.

The original source installer and console retain the complete predecessor /
successor chain. A completed predecessor cannot satisfy the exit condition
while a successor owns SQL, native handles, readiness or a running host. On
failure, retry only justified original cleanup or exact ACK settlement; never
launch a replacement because a wait timed out. No user process is stopped.
Clean retirement without an explicit successor request continues to leave
daily admission fenced, as it does today.

## Verification and completion evidence

Use isolated ledger/source/journal fixtures and explicit synthetic native
collaborators for source tests. Verify positive original completion, retained
preimages, copy/replacement/thread/PID refusals, old-generation rejection,
queue/exemption/history preservation, exact transaction rollback, lost ACK,
unknown close/guard custody, fresh readiness, both supervisor Create checks and
the source installer's final exit predicate. Source tests prove no native gate.

This contract precedes implementation. The public README must keep the restart
gap open until the actual retained successor, transaction, host/CLI integration
and source tests are complete. Native activation/restart and monitoring cost
remain separately unverified; implementation cannot activate the daily runtime.
