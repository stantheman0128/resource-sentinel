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

The original retirement inventory retains adaptive lifecycle rows and the
experiment archive subset; it does not retain ordinary queue, worker, exemption
or general execution-archive payloads. Do not claim those were captured at the
old seal. Capture their complete bounded current contents under the new original
POLICY guard and require equality again in the final transaction. Compare all
actually retained predecessor rows against the old snapshot, allowing only the
original ACTIVE-to-DRAINING seal, its exact FROZEN-to-SEALED retirement row, and
the old nonce-to-new-original-guard nonce change. This check preserves current
ordinary rows without inventing earlier observations; no ordinary row is
changed by succession and private payloads stay local.

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

Generation transfer preserves the current runtime guardian epoch and all
historical provenance. A later, separately retained successor epoch publication
may advance that current epoch and registry revision before the first fresh
guardian Create. The existing SettledEpochRollover contract cannot supply this
proof: its old guardian handle and held supervisor instance have already been
positively closed by daily retirement. Never reopen them or fabricate that audit.

The successor epoch operation requires the exact acknowledged successor and
fresh supervisor/startup, its newly acquired original instance lease, complete
bounded terminal/experiment/control history, and the completed original
retirement. Premint its attempt and new epoch once. Under a distinct original
POLICY guard, atomically insert an immutable successor-specific audit and CAS
only runtime epoch/logon/revision; increment the revision once and preserve all
ordinary allocations, queue, exemptions and historical rows. The new epoch must
be absent from managed history and both epoch-audit routes. A failed SQL/native
close, unknown acquisition or nonce cleanup retains the same operation; no
guardian Create precedes positive original commit/close/POLICY/readback evidence.

The canonical `adaptive_successor_guardian_epochs` audit binds schema_version,
attempt_id, transition_id, successor_generation, succession_sha256, old_epoch,
new_epoch, supervisor_pid, supervisor_created_filetime_100ns,
supervisor_logon_id, supervisor_instance_id, policy_instance_id, policy_logon_id,
previous_revision, registry_revision and inventory_digest. All fields are bounded
scalars, included in the shared 4096-row/16 MiB history accounting. UPDATE/DELETE
are forbidden. The original startup checks revalidate this distinct route both
initially and immediately before Create. Guardian registration must validate
this exact current generation/transition/archive/POLICY/epoch/revision plus
complete obligation checks and its own original live self handle; ambiguous
audit routes refuse. The generic fresh and ordinary rollover paths stay intact.

Retain the exact fresh SupervisorStartup before its first identity, SQL or
instance-mutex acquisition. Its acquisition and freshness inspection use a
tracking-only lexical SQL owner, including initial binding reads and justified
original retries. This owner does not bypass normal readiness or POLICY checks.
Unknown SQL acquisition/close cannot become a clean startup close or authorize
a new owner merely because no acquired instance lease was returned.

The new guardian validates current historical data under its own original live
self witness, registration operation and POLICY guard. It does not reconstruct
the predecessor's retired native custody from the audit. Before its final short
transaction, retain a complete bounded schema/ledger/receipt/journal observation
through original tracked readers; bind the opaque snapshot to the exact guardian,
registration, guard, thread/process, ledger and journal identities. Revalidate
the full SQL observation in the final transaction without native or filesystem
I/O there. Capture validates canonical archive/audit links, terminal and closed
experiment receipts, restored control/action history and absence of managed
obligations. Ordinary nonmanaged allocations and queued work remain untouched.

Lost registration COMMIT acknowledgement uses the same original snapshot and
preminted publication images. Validate only its exact guardian infrastructure
insertion, one registry revision increment, and original nonce or positively
cleared nonce as the owned postimage changes. Preserve exact adaptive historical
evidence; separately bound ordinary nonmanaged rows again, allowing their
independent legitimate postcommit changes because registration never writes
them. No changed adaptive history, unknown SQL owner or reconstructed snapshot
can substitute for original settlement. The prepublication epoch validator
continues to require its exact audit revision; the registration's +1 postimage
is a separate original-operation check, never a global revision relaxation.

Fresh readiness construction has a private original-host bootstrap check;
public/local admission stays fenced until that exact retained listener is
published with its serving thread, service and registry positively bound.
Metadata acknowledgement alone is not readiness, and readiness alone is not
permission to bypass the fresh supervisor or epoch checks above.

The original source installer and console retain the complete predecessor /
successor chain. A completed predecessor cannot satisfy the exit condition
while a successor owns SQL, native handles, readiness or a running host. On
failure, retry only justified original cleanup or exact ACK settlement; never
launch a replacement because a wait timed out. No user process is stopped.
Clean retirement without an explicit successor request continues to leave
daily admission fenced, as it does today.

Both resident console entry points expose `--restart-after-retirement`, default
off, requiring `--retire-generation-after-drain`. The source installer also
requires the separately authorized `--apply-daily-accounting-handoff`; review
mode cannot request a successor. Reject incomplete option combinations before
loading preparation/manifest data or creating an installation/runtime owner.
The flag requests one successor, not recursive automatic retirement/restart.
The original installation retains its first host by object identity throughout
that host's complete chain. Both entry points accept a normal return only when
`chain_retirement_complete()` positively verifies that exact chain; a retired
predecessor or a replacement host cannot authorize process exit.
An exception while inspecting that chain, including an original successor's
quarantine, is retained as failed exit evidence. Status reporting cannot turn
that exception into process termination. The direct console keeps servicing
and pacing the same original chain after an unexpected resident-loop return;
it does not create a replacement or retry unknown native/SQL ownership.

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
