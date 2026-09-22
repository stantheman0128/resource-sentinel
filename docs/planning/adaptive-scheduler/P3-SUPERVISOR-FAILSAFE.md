# C4: supervisor failsafe and bounded reconciliation

2026-09-22. Contract for README ruling ④, written before implementation.
This document specifies required behavior; it is not implementation or test
evidence. [README](README.md) remains the only progress and gap index. It records
the source commits, executed test counts and outstanding gates separately.

## Scope and governing decisions

The supervisor keeps the original single-writer architecture. It supervises
Sentinel infrastructure, restores only owned controls after positively witnessed
guardian death, and reconciles exact ledger obligations. It never restarts a
workload, kills a workload, treats an expired lease as death, modifies a user
exemption, or creates capacity from a lower capped measurement.

Plan §§3.2, 7.4 and 8.3 apply with the existing user clarifications:

- [All-witness loss](P3-RETAINED-SUPERVISOR.md#contract-clarification-for-all-witness-loss)
  remains UNKNOWN and performs no restore. A missing, reused or inaccessible
  PID, a persisted heartbeat, and an abandoned mutex do not prove old guardian
  death. This contract does not introduce a weaker historical-death test.
- [C3 finished-Job barrier clearing](BARRIER-CLEAR-FINISHED-JOB.md) accepts the
  durable, exact finalization proof of a natively empty, sealed and restored
  Job. A restart may finish that ledger-only clear without reopening a Job
  that no longer exists. Running Jobs still require the original five fresh
  uncapped samples.
- [C2 prelaunch retirement](P3-PRELAUNCH-RETIREMENT.md) requires original
  guardian evidence and its durable receipt. Supervisor recovery cannot
  manufacture a never-created or never-associated proof from an empty name.

Adaptive remains off by default. External supervisor restart configuration,
Scheduled Task installation and changes to daily runtime are not part of this
source change. Conditional recovery must not be reported as an unconditional
self-healing or timing guarantee.

## Startup authority and singleton ownership

Startup acquires a native supervisor-instance mutex before examining candidates
or creating a child. Its namespace is tied to the exact persisted POLICY
instance and logon, has the normal explicit logon ACL, and is distinct from
POLICY, the recovery-instance mutex and every Job mutex. Keep it for the whole
host lifetime; use bounded acquisition and no recursive acquisition. Failure,
unknown acquisition/release, or conflicting instance binding prevents child
creation. Abandonment permits inspection only, not a death or restore claim.

While that mutex is held, read a bounded, validated snapshot of infrastructure,
runtime identity, active scopes, launch obligations and the control slot. The
existing bounds remain 32 infrastructure rows and 10 concurrently managed Jobs.
Page terminal history with a stable revision/cursor; a partial scan is not a
complete inventory. An unreadable or malformed ledger is HOLD. Revalidate the
snapshot under POLICY before publishing a changed startup decision.

Only an empty, verified startup state may create a new guardian. For this C4
deliverable, a fresh supervisor encountering any existing guardian/helper row,
unresolved old scope or old guardian binding returns `COLD_RECOVERY_HOLD` and
creates no child. It performs no native Set or restore. A registry row is a
candidate locator, never an OS liveness claim. Do not delete unknown rows to
make space. A new mutex cannot establish that an older supervisor, which did
not use this protocol, is absent; mixed versions cannot be certified by this
mutex alone. No-existing-infrastructure and complete scope/binding checks
remain mandatory even when acquisition succeeds.

The current infrastructure role row has PID, creation FILETIME and logon but
no authenticated guardian epoch/version publication. It cannot confer the
runtime epoch on an arbitrary process. This item therefore does not implement
cold ALIVE adoption. Its refusal reports that concrete missing provenance;
operational item 4 must either supply and verify the publication protocol and
its callers or continue to report cold adoption unsupported. No normal-mode
promotion follows from merely locating or opening a process.

## Witness states and allowed transitions

| Available evidence | Allowed action | Forbidden inference/action |
| --- | --- | --- |
| No old process handle; opening exact candidate fails or yields UNKNOWN/mismatched identity | Keep explicit cold-recovery HOLD and report exact unresolved scopes | PID absent means DEAD; registry deletion; restore; release; competing guardian |
| Fresh host locates an old candidate, including a full-identity ALIVE observation | Report cold adoption unsupported and keep HOLD until an authenticated epoch/version publication contract is implemented | Treat registry identity or ALIVE alone as ownership; restore while alive; silently replace the old guardian |
| Supervisor has continuously retained its own verified child creation witness, now DEAD before first attach | Capture recovery binding using that same exact witness, reverify DEAD under fences, then restore/drain known obligations | Reopen by PID as replacement evidence; treat early death as absence of work |
| A normally captured exact witness becomes DEAD | Existing compare-and-restore and orphan drain, with all existing checks | Release solely because the owner died |
| Exact FINISHED durable proof with RESTORED slot and settled manifest | C3 ledger-only barrier reconciliation | Finish another scope; remove an unknown infrastructure row; alter native controls |

If operational item 4 later implements positive ALIVE adoption, it must be
prospective witnessing: first authenticate the guardian publication, observe
and retain the exact living process object, then rely on that same handle
becoming signaled later. It must not infer a past death from PID history. An
adoption/capture race must preserve acquired ownership and fail closed. This
paragraph defines the boundary of that future work, not a C4 implementation or
acceptance claim. Any unfinished native ownership or cleanup stays reachable
and quarantined according to the existing handle contracts.

The early-death entry must be distinct from ordinary `RecoveryOwner.capture`.
It takes a trusted in-process retained creation witness, not a CLI boolean or
serialized handle number. Verify exact guardian identity/epoch, current owner,
persisted POLICY binding and logon, duplicate the retained witness, and verify
DEAD before and inside the existing recovery-instance/POLICY/Job fences. Each
manifest must still match the original guardian. Immutable creator identities
and epochs are not changed. DB failure before capture is HOLD; only an already
captured binding retains the existing DB-independent withdrawal capability.

If a child died before its first scope registration, the same retained death
witness plus a complete POLICY-fenced absence of scopes belonging to that
child can retire its infrastructure row without opening a Job. This relies on
the production ordering: `register_job_scope` commits before initial manifest
publication and native Job creation. It does not apply to a scope that was
registered but has a missing manifest, unknown Job creation or unknown launch.
Those are obligations, including when no allocation or process is visible.

## Registry cleanup is an independent obligation

Keep a pending retirement object for each exact dead guardian/helper until its
row cleanup is verified. Replacement state and replacement budgets do not own
that obligation. An exhausted budget, refused replacement, unattached guardian
or successful close must not turn an outstanding cleanup into `absent`.

Every tick attempts each eligible pending cleanup at most once, with bounded
work. It re-observes the retained exact witness and permits deletion only for
DEAD. UNKNOWN, mismatched observation or unresolved handle cleanup holds. A
replacement helper starts only after the old exact row is verified removed or
already absent. A guardian replacement additionally requires the complete
settlement and epoch transition below. No tight retry loop or recursive child
creation runs inside one tick.

The pending object retains role, identity, witness, binding, original
`PolicyGuard` when one was committed, operation outcome and cleanup ownership.
This is required because a ledger failure can leave `policy_entry_nonce`
intentionally occupied; calling `prepare()` again would stay busy forever.

For a retained same-process attempt whose native fence was released with a
known outcome, retry by reentering `hold` with the **same guard**, acquiring the
same native mutex and revalidating its exact nonce/binding before touching the
ledger. Repeat only the idempotent DELETE of that role/PID/birth/logon. An absent
exact row after lost acknowledgement is a completed deletion, not permission
to remove a replacement's row. Only a known successful transaction and cleanup
allow normal nonce release.

Changed nonce/binding, uncertain mutex cleanup, missing guard ownership or
ambiguous native handle state stays quarantined. Do not clear arbitrary pending
nonces, reconstruct guards from status files, or retry numeric handles with
uncertain close outcomes. If the supervisor itself dies during this cleanup,
the same-process guard retry cannot be fabricated by its successor. The new
host reports the exact unresolved POLICY operation; any separate recovery of
that operation needs its own accepted authority contract.

## Finished-Job barrier janitor

Run a bounded ledger reconciliation at startup and every tick, independently of
whether guardian attachment or replacement is possible. It examines only the
single control slot's exact execution. It does not scan process names or create
a native Job. Under POLICY, require all existing C3 evidence:

1. `RECOVERY_HOLD` and an exact `RESTORED` slot belonging to the execution,
   nonce, original guardian epoch, owner and logon.
2. A top-level `FINISHED` row with sealed launch and no launch in flight.
3. `assert_retained_terminal` succeeds for the exact settled manifest, no live
   allocation, and exactly one matching `managed_finished` archive.
4. Original control disabled, no pending intent, and no applied own cap.
5. Exact execution revision and registry-revision CAS at the final transaction.

Use `assert_finished_barrier_clearable` and
`clear_recovery_hold_finished_locked`; retain their atomic audit write. Lost
acknowledgement is reconciled from the resulting barrier/audit state and must
not append duplicate evidence. An unavailable or contradictory prerequisite
keeps HOLD and is retried only when its existing cleanup contract permits it.
Prelaunch C2 receipts and cascaded child FINISHED rows cannot substitute for
this top-level native-empty proof.

This path requires no new historical-death inference: it changes no OS setting
and releases no allocation. If a retained Job handle happens to reveal a live
member or active cap contradicting the durable finalization, report integrity
failure and do not clear. The absence of such a handle is not independently
used as proof of emptiness.

## Epoch rollover after complete settlement

Minting a new guardian epoch is insufficient: current scope registration refuses
a new epoch while `adaptive_runtime.guardian_epoch` still names its predecessor.
Add one explicit rollover operation rather than rewriting old execution rows.

The operation holds the supervisor-instance mutex and POLICY. It revalidates
the old exact guardian's retained DEAD witness, complete old-epoch inventory,
runtime instance/logon/epoch, and the expected registry revision. All named old
scopes must have passed their formal terminal proof: FINISHED uses its exact
archive/settled manifest; C2 outcomes additionally require their retirement
receipts. No active allocation, launch in flight, START_UNKNOWN, unretired scope,
HELD control slot, pending native intent, pending cleanup owner or unresolved
barrier may survive. A partial historical scan is insufficient. A living orphan
child keeps the old epoch and its capacity; it is not migrated or restarted.

Persist the transition and its audit atomically, using a freshly minted epoch
which has never owned work. Do not reuse an earlier epoch. Couple publication
of the replacement's exact identity to that startup attempt before allowing
normal enrollment; a failed/unknown replacement start remains a pending startup
obligation rather than causing repeated reminting. Historical manifests, creator
identities, terminal receipts and allocation archives stay immutable. Rollover
does not change mode, profile, resource limits or exemptions and does not grant
capability approval.

If the old runtime is blank and has no guardian-owned obligations, ordinary
fresh startup uses the same bounded inventory and instance exclusion. If the
old writer is unresolved, rollover stays refused even when every visible Job
appears empty. All-witness loss cannot be hidden inside an epoch reset.

## Minimum deliverable and deviations

The C4 deliverable is production host wiring for all of the transitions above,
with portable regression evidence and accurate HOLD diagnostics. It includes
actual startup exclusion and candidate inspection, explicit cold-adoption
refusal, creation-witness early-death recovery, per-tick independent registry cleanup,
finished-barrier retry and settled epoch rollover. A class or helper with no
production caller is incomplete. Merely retrying a permanently busy POLICY
entry is incomplete as well.

This clarification extends when recovery binding may be captured while keeping
the same positive retained-handle death evidence. C3 barrier evidence and C2
retirement evidence are reused, not broadened. No automatic all-witness-loss
recovery or unauthenticated live adoption is added. The incomplete cold-adoption
path stays explicit in the operational item 4 scope rather than being described
as recovered. Guardian remains the only normal actuator; the supervisor
does not assume normal control of running orphan Jobs. External restart remains
a separately verified deployment prerequisite, and native gates remain blocked
or unverified until measured from a capable app-external console.

## Required executable evidence

Tests use isolated real SQLite/journals with explicitly synthetic native
backends for portable behavior. Their names and commands belong in README when
implemented and executed; this contract records no passing test count.

| Area | Required positive and negative cases |
| --- | --- |
| Singleton/startup | Concurrent starts serialize; invalid/mixed binding and incomplete inventory create no children; existing unresolved guardian prevents a second normal writer. |
| Cold-adoption refusal | Existing infrastructure always prevents Create/Set/release in a fresh host; even a matching ALIVE process is insufficient without the unsupported publication protocol; missing PID, PID reuse, inaccessible identity and UNKNOWN never become DEAD. |
| Early death | Created child dies before attach, before registry publication, and after scope registration; retained witness is used; unreadable binding and missing manifest hold; no second Create or fabricated C2 receipt. |
| Cleanup retries | First DELETE failure then success; commit before lost ACK; exact row already absent; changed nonce/binding; observation UNKNOWN; uncertain native release; retries continue after replacement budget exhaustion. |
| Barrier janitor | Restart between FINISHED commit and clear; Job name no longer exists; one atomic audit; corrupted/missing archive, live allocation, pending intent, other slot and revision race all hold. |
| Rollover | Complete old settlement enables a fresh epoch; each unresolved launch, child, slot, manifest, cleanup owner or unknown dead-writer witness prevents transition; old provenance remains unchanged. |
| Host integration | Startup/tick invokes the real consumers against the same ledger; failure in one bounded cleanup does not silently drop other obligations; status distinguishes alive, dead, unknown, pending cleanup and blocked recovery. |

Run affected portable modules through normal `invoke-sentinel.ps1` admission,
then the adaptive regression tree. Use the interpreter identified by
`sys._base_executable`, never the `py` launcher for native tests. Record actual
commands, environment, failures/errors/skips and native capability refusals.
Portable success is not evidence of native S1-S3, guardian-loss timing, P4
overhead, P5 fault recovery or P6 A/B performance. No test may crash, stop,
limit or trim a user's working process.
