# P3 item 4: operational lifecycle, exact release and rollback commands

Date: 2026-09-22. Status: **implementation contract; native acceptance pending**.

This document specifies the remaining operational integration required by
[IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) sections 3, 4, 7, 10/P3 and
11.5. It preserves [C2 prelaunch retirement](P3-PRELAUNCH-RETIREMENT.md),
[C4 supervisor failsafe](P3-SUPERVISOR-FAILSAFE.md), and the
[finished-Job barrier contract](BARRIER-CLEAR-FINISHED-JOB.md). It is not evidence
that the commands below already exist or that P3-P6 passed.

Production adaptive remains off. This implementation does not install a
Scheduled Task, change daily configuration or global agent entrypoints, start a
daily controller, or authorize production native-control experiments. All
mutation tests use isolated ledgers, journals, endpoints and owned fixtures.
The 58 GiB machine budget, physical/Commit 4 GiB reserves and atomic maximum of
three user exemption leases remain unchanged. No workload kill, RAM hard cap,
periodic suspend/resume or new CPU/IO/trim writer is introduced.

## 1. Observed implementation boundary

The following are existing APIs, inspected before this contract was written:

| Existing API | What it establishes | Integration still required |
| --- | --- | --- |
| `Coordinator.admit_managed(context, ...)` | Admission from an original in-process `ManagedAdmission`, with exact execution/allocation binding | Matching exact prelaunch abandonment entrypoint and wrapper failure integration |
| `Coordinator.release(...)` | Legacy release that skips every bound managed allocation | Preserve this protection; do not turn owner PID, command or PostToolUse success into managed release authority |
| `ManagedAdmission.cancel_reserved(...)` | Original native self identity plus an exclusively retained unused launch credential; exact RESERVED cancellation and replay | Invoke only through the same retained context and the appropriate pre-handoff boundary |
| `ManagedLauncher.retire_before_start(...)` | Authenticated named-scope CancelBeforeStart/StartFailed with guardian evidence and stable replay | Wrapper failure/interrupt recovery; it is not a substitute for RESERVED cancellation |
| `ManagedLauncher.close_local()` | Closes local custody after verified transfer/root exit or acknowledged retirement | Closing does not release capacity; submitted unresolved attempts deliberately refuse |
| `WrapperHost.release()` | Currently attempts only `close_local()` after refusal | Must settle or retain exact abandonment work instead of reporting close failure and losing the only owner at normal exit |
| `GuardianLifecycle.reconcile()` / `close_terminal()` | Reconcile proves native empty/disabled and commits FINISHED; a separate method closes retained terminal owners | Host integration and retry-safe terminal cleanup; terminal entries otherwise remain in the retained inventory |
| `GuardianControl.begin_drain()`, `tick()`, restore/frame methods | Stops new restrictive control through the consumer; existing native restoration and observation paths | Persistent host drain state, operator protocol and complete status/audit reporting |
| `GuardianSupervisor` and retained C4 operations | Recovery using original creation/process witnesses; exact registry/barrier retries | Intentional drain must prevent replacement while these obligations continue |
| `query_adaptive()` and `sentinelctl.py adaptive-query` | Bounded read-only diagnostics without constructing migration-owning services | Operational status/discovery and explicitly qualified native audit |

At this boundary there is no operational endpoint discovery or authenticated
operator stop protocol. Wrapper endpoint identity is supplied manually. The
existing helper control endpoint accepts the registered helper, not arbitrary
operator clients. A mode row, descriptor, terminal label or missing PID is not
native restoration or release evidence.

## 2. Public command contract

Retain the formal plan's command names under `scripts/sentinelctl.py`:

```text
sentinelctl.py --data-dir <explicit-directory> run-managed <managed-command-options>
sentinelctl.py --data-dir <explicit-directory> adaptive-status
sentinelctl.py --data-dir <explicit-directory> adaptive-mode --mode off --drain
sentinelctl.py --data-dir <explicit-directory> adaptive-recover --restore-only --verify
sentinelctl.py --data-dir <explicit-directory> adaptive-audit --require-no-active-caps
```

These are interface forms, not instructions to target daily runtime. The new
operational commands require an explicit target directory. `run-managed`
preserves the existing wrapper's explicit command, cwd, repository identifier,
role, priority and resource estimates. Discovery can supply endpoint locators;
it cannot supply admission or launch authority. Existing manual endpoint options
may remain for diagnostics, with the same native verification.

`adaptive-mode --mode off --drain` is the full spelling of the requested
"mode off --drain" operation; `adaptive-audit --require-no-active-caps` is its
audit companion. This item adds no promotion-to-canary/limited shortcut.

The default operational invocation performs one bounded RPC attempt and returns
its result, including pending when work remains. An optional `--wait` requires a
bounded timeout and observes that same operation/instance. It does not resubmit
new mutation identities, retarget another epoch or cancel owner work when the
observer's timeout or interrupt ends the wait.

| Command | Required behavior | Meaning of success |
| --- | --- | --- |
| `run-managed` | Create one original wrapper context; admit once per exact request; launch at most once; preserve stdio/root exit; handle abandonment through section 3 | The root's actual exit is reported separately from remaining child/accounting custody; there is no automatic unmanaged fallback |
| `adaptive-status` | Read bounded diagnostics and, when available, request authenticated live status | Successful observation, not restored caps, empty Jobs or permission to control |
| `adaptive-mode --mode off --drain` | Request a monotonic freeze/drain on the existing owner; stop enrollment, tightening and renewal; retain restoration/lifecycle services | Report acceptance and each verified outcome separately; an accepted request with remaining work is `rollback_draining`, not `rollback_complete` |
| `adaptive-recover --restore-only --verify` | Ask the current original guardian or already retained supervisor recovery owner to reconcile owned restrictions and report native readback | Verified results for the complete applicable inventory; unavailable custody remains unverified, never reconstructed |
| `adaptive-audit --require-no-active-caps` | Query a complete bounded/paged inventory, its live owner bindings, native disabled observations and exact retired-scope evidence | All applicable owned caps are verified disabled or their scopes are positively retired, with no unknown/conflicting/incomplete item; this does not by itself mean all workloads exited |

Status/audit readers must not create a missing DB, migrate schema, initialize
POLICY, write mode, clear a barrier or repair a manifest. Dispatch these commands
before the legacy CLI constructs `Coordinator`. A missing/incompatible ledger
or owner is a structured unavailable result. Reuse the read-only SQLite pattern
in `query_adaptive`; do not use a writable service merely to inspect state.

Control records go to stderr for `run-managed`; stdout remains the workload's.
Other operational commands may return one bounded JSON result on stdout. Do
not export commands, environment, workload output, claim tokens, HMAC keys or
arbitrary exception text. Preserve stable reason codes and exact IDs; FILETIME
values use decimal strings.

## 3. Same-owner abandonment and exact capacity release

Provide one retained launcher-level abandonment operation, with a narrow
Coordinator adapter for the existing `ManagedAdmission.cancel_reserved` path.
An adapter accepts the original context and exact allocation/revision; it does
not accept caller-supplied proof, a serialized context, a raw PID or a boolean
claim that no process started. Mirror compatibility data only after an
acknowledged authoritative outcome; mirror failure never changes that outcome.

Record irreversible handoff boundaries before attempting the side effect.
Human-readable phase names are diagnostics, not the sole authority. In
particular, distinguish submission unknown, Prepare attempted, claim exported,
native Create attempted, retained root available and Bind acknowledgement.

| Retained evidence/boundary | Allowed failure cleanup |
| --- | --- |
| No submission attempted | Close only owned local resources |
| Exact queued request, with no allocated execution/claim obligation | Seal this attempt and cancel only its request key and exact owner binding; never cancel the owner's entire queue |
| Exact RESERVED allocation, original unused credential, no competing handoff possible | Call `cancel_reserved` with the original context, reservation and revision; preserve its seal, replay target and result across failure |
| Admission result lost | Reconcile using the original context and request binding; do not create a new context or assume denial from absence of an ACK |
| Prepare/claim was sent or may have committed | Retain original request IDs and context; resolve the named scope/retirement path through the original guardian. A row observed as RESERVED alone does not prove no in-flight handoff |
| Named scope, positively never-started case | Use existing CancelBeforeStart/StartFailed RPC; C2 guardian proof and atomic receipt authorize release |
| Claim crossed, Create unknown, root retained, or work may exist | Cancellation may be pending. No automatic command replay or prelaunch failure claim; retain demand until positive lifecycle evidence |
| Root exited and guardian accepted custody | Return root exit normally and close eligible wrapper handles; guardian retains children, allocation and exclusion until actual Job completion |

Timeout, Ctrl+C/KeyboardInterrupt, RPC acknowledgement loss, SQLite failure and
connection/native cleanup failure all pass through the same retained owner.
An interrupt must not bypass ownership publication. A normal wrapper exit must
not discard its only unresolved local launch/cleanup witness. Return a bounded
pending report and continue the permitted same-owner reconciliation, or hand
off only through an existing positively acknowledged custody contract. A second
interrupt is not release evidence. External process death remains a recovery
case, not an implemented clean shutdown path.

Preserve native exception owners and original `PolicyGuard`/request objects.
Known transient ledger failures may retry idempotent work under the same guard
after exact nonce/binding checks. Unknown acquire/release/close outcomes stay
quarantined. Do not clear an arbitrary nonce or re-use a potentially closed
numeric handle. The distinction remains visible in refusal results.

Never overload legacy `release --owner-pid` to finalize managed rows. A new CLI
process has neither the original unused credential nor the original native
wrapper witness; it cannot recover that authority by reading the DB. Operator
recovery is routed to a currently authorized retained owner instead.

## 4. Terminal native custody and cleanup

Native Job emptiness, terminal SQL state, capacity release, barrier settlement
and handle cleanup are separate facts. The host must eventually retire a
finished lifecycle entry; otherwise its retained inventory never drains.

Before beginning terminal cleanup, require the existing exact proof chain:
sealed launch/no launch in flight, retained Job queried empty, own CPU control
disabled, settled exact manifest, FINISHED revision and exactly one matching
archive with no active allocation. Settle this execution's applicable control
slot/barrier using C3. A missing in-memory control episode does not prove that
there is no durable control obligation. Conversely, an execution that never
owned a control slot must not be trapped forever by `control_episode_unrestored`;
prove that no applicable obligation exists under the existing fences.

Publish a retained cleanup state only after proof and proof-scope cleanup have
completed. It records the immutable exact terminal binding and the original
root/wrapper/Job/mutex owners. Subsequent attempts verify durable binding and
retry only eligible original owners. Once native close starts, do not return
to normal reconciliation that queries a now non-queryable Job or acquires an
uncertain mutex. Known successful closes are tombstoned; positively known close
failure may retry under that native object's contract; ambiguous outcome and
interrupt retain custody and quarantine the locator.

Only completed cleanup removes the lifecycle entry from retained inventory.
Do not erase recovery manifests, retirement receipts or history to make drain
appear complete. Contradictory retained native observations override a proposed
ledger-only success and preserve recovery HOLD.

## 5. Live discovery is a locator protocol

The namespace is `<explicit-data-dir>/adaptive-host/`, using the project's
explicit ACL and protected publisher machinery. The supervisor owns the
canonical instance descriptor. Its guardian's ready endpoint metadata is
cross-bound to the exact child identity retained from creation, policy instance,
logon and guardian epoch. The supervisor must validate that child-bound metadata
before presenting the instance as ready; it cannot infer readiness from a file
name, registry PID or startup message alone.

A directly launched guardian remains reachable through explicit endpoint
arguments only. It does not publish a canonical complete-instance claim or
claim that a supervisor has accepted its drain/recovery obligations. This item
does not infer an instance topology from unrelated descriptors.

Publish a bounded versioned descriptor only after the host's corresponding
identity/instance ownership and listeners are established. Bind at least:

- tool/protocol version, policy instance, logon, guardian epoch and host role;
- complete native host identity, endpoint instance IDs and endpoint roles;
- startup/draining availability as reported state, not native proof;
- a revision/instance identifier that permits exact replacement and cleanup.

Use the project's explicit logon ACL and protected-namespace practices. Publish
atomically; validate size, schema, identity, path ownership and binding before
use. Descriptor removal must compare the original instance so an old process
cannot delete its successor's record. No secret launch credential belongs in
the descriptor. Missing/partial/stale/conflicting descriptors are unavailable.

The client pins the advertised complete server identity, connects through the
native pipe transport, verifies the same process object and authenticates a
live response bound to endpoint instance, epoch, policy binding and request.
Creation-time mismatch, PID reuse, peer death and changed binding refuse the
operation. File age or PID presence is never readiness.

Discovery does not add cold adoption. A fresh supervisor with old state remains
`COLD_RECOVERY_HOLD` under C4 even if it locates an ALIVE guardian. Requests may
reach that original guardian as its operator, but the requester does not gain
guardian/supervisor mutation ownership. An unavailable owner is not permission
to create a competing recovery writer. Serialized handles or a descriptor
cannot recreate a lost original process witness.

## 6. Separate operational protocol and intentional drain

The supervisor coordinates a full instance drain. A guardian-only explicit
endpoint operation remains guardian-scoped and must report that scope; it
cannot acknowledge suppression of supervisor replacement. The CLI's default
bounded request and optional bounded observer wait follow section 2.

Use a separate typed operator endpoint/protocol. Do not register a CLI as helper,
reuse the helper endpoint's privileges, or expose `apply`/`Set` to operators.
The minimal operation set is describe/status, mode-off-and-drain, restore-only
reconcile, and audit. Each request binds an exact target instance/epoch and
contains a stable request ID. Mutation requests are monotonic/idempotent; an
exact lost-ACK replay must not reset drain, extend a control lease or repeat a
launch. Conflicting payload under one request ID refuses.

Authenticate the OS pipe peer's complete identity and same logon while holding
the verified peer handle through the operation. A small bounded initial identity
envelope may identify the expected caller, but its claim must be verified before
acting. Pin and verify the exact server too. The accepted cooperative same-user
model permits a same-logon operator to request only the named tool instance's
conservative operations; it does not claim hostile same-SID isolation. A new
boolean such as `user_authorized` is not native peer authentication.

The guardian persists drain intent in its retained in-process state before
acknowledging it: no new managed enrollment, tightening or renewal. Restore,
uncapped frames, queries, lifecycle heartbeat and cleanup remain available.
`GuardianControl.begin_drain` is only the control portion of this transition;
the host must also stop serving launch requests on later ticks. Safety ticks
still precede bounded RPC waits and follow reconciliation.

An off-mode ledger/config record states desired policy. It cannot attest to OS
restore, process exit or released capacity. Change applicable durable policy
through an explicitly fenced operation, retaining any failed transaction/guard.
Apply the formal recovery barrier to new non-exempt admission while recovery is
unverified; preserve the existing exemption authority and release criteria.
Already owned native restore must not depend on a new successful SQLite write,
fresh capacity, successful capability promotion, or helper availability.

The supervisor records intentional drain before sending child requests and
suppresses both guardian and helper replacement while the stop operation is
active. It continues original-witness recovery, registry retirement, barrier
reconciliation and cleanup. A guardian death during drain still requires restore
through the retained C4 owner, but it does not trigger normal-policy replacement.
A new supervisor after loss of this in-memory state remains subject to C4 cold
HOLD; discovery or an untrusted stop marker cannot bypass it.

Helper stop uses its existing stopping/restore reconciliation semantics; it
must not send new restrictions. Do not stop necessary observation while live
restored executions still need uncapped evidence. Workloads continue naturally.
Only when all relevant native/lifecycle/cleanup obligations have settled may
the cooperating hosts exit and the supervisor retire their exact registry rows
using retained death witnesses. No `taskkill`, process-tree kill or forced cold
adoption is part of this item.

### Fenced off-mode transaction

Add a host-owned `FencedOffOperation`, implemented as an adapter around the
existing `RetainedPolicyOperation`. The supervisor's authenticated operation
coordinator retains it; CLI code never writes mode directly. It accepts only
the conservative off request, binding its request ID/payload to the existing
policy instance/logon, guardian epoch and expected registry revision. No daily
config file is written. No field in the request supplies native authority.

The operation follows the actual POLICY lifecycle:

1. Retain the operation before the first side effect. Latch intentional drain
   in the original host so creation/replacement and normal policy cannot resume
   while the transaction or its acknowledgement is pending.
2. Use `PolicyCoordinator.prepare` and `hold` through the retained adapter;
   validate the current host instance authority and exact binding. Contention
   is pending. An existing nonce without its original guard is not reclaimable.
3. Collect necessary native/owner evidence outside a SQLite write transaction.
   While POLICY is held, revalidate its binding, guardian epoch and revision in
   the short transaction using `policy.revalidate(conn, guard)`. A changed epoch,
   instance, logon or stale expected revision cannot authorize a different
   target. No pipe/native wait runs under the SQLite write transaction.
4. Atomically set `mode='off'` and set `admission_barrier='RECOVERY_HOLD'` if
   relevant ownership or control recovery is unsettled. Incomplete/unknown
   recovery evidence does not qualify as settled. Otherwise preserve the
   barrier already present; this operation never changes a barrier to `NONE`.
   A HELD control slot, pending intent or unsettled applied-cap episode cannot
   be classified as settled merely because one native read currently says
   disabled. Existing slot/barrier consistency rules still apply.
5. Make the runtime change one conditional update under the exact expected
   instance/logon/epoch/registry revision and original POLICY nonce. Increment
   registry revision exactly once for an actual changed runtime state, check
   the affected row count and preserve all unrelated runtime fields. Do not
   independently update mode and barrier across transactions. An already exact
   target state can be an idempotent no-op only after the same binding and
   recovery checks, without clearing any other owner's obligation.
6. Commit, verify the operation outcome, and complete native/connection/POLICY
   cleanup before reporting the off transaction as settled. The acknowledgement
   distinguishes committed mode, drain acceptance, native restoration and
   bookkeeping; none implies the others.

Retain the original guard, expected preimage, intended postimage and request
identity when SQL or acknowledgement is uncertain. Retry at most one bounded
attempt per tick under the same guard when its native release is known and its
nonce/binding still match. After a lost transaction acknowledgement, reconcile
the exact original conditional update; do not repeat its revision increment or
blindly replace the expected revision with the latest one. If another legitimate
revision intervened and the original effect cannot be established, report
unknown rather than fabricate an exact replay receipt. An observation that
mode is off is not by itself proof that this request committed.

Use the retained operation's existing quarantine rules for interrupted/unknown
native scope cleanup, changed nonce or lost owner. Publish custody before a
possible interrupt even when no latest result has been assigned. Exact request
replay uses that retained operation; a different payload under the same request
ID refuses. A descriptor, old response or later CLI process cannot reconstruct
the missing guard. No new off-mode operation grants restore-only authority.

`RECOVERY_HOLD` without a control slot is valid under the existing
`control_slot._barrier_consistent` rule. The current finished-slot janitor does
not supply a general no-slot recovery-clear procedure, however. If this
operation raises such a hold, it must retain/report the concrete unresolved
ownership and use a separately valid positive recovery path before admission
can reopen. Neither an off no-op nor an empty slot may clear it. Unsupported
no-slot recovery remains a reported HOLD; tests must not delete the barrier to
manufacture completion.

## 7. Results, unknown replies and audit boundaries

Every operational reply distinguishes at least request accepted, desired mode,
observed host/drain state, inventory completeness, native disabled state,
bookkeeping/slot/barrier settlement, remaining execution/custody count and stable
reason. Use unknown/null where evidence is unavailable. A boolean success must
not collapse these states.

If a mutation request times out after possible delivery, return outcome unknown
with the original target and request identity. Query/replay that same operation;
do not silently target a replacement epoch. A CLI disconnect does not cancel a
drain already accepted by its owner. A fresh CLI can observe a live operation,
but cannot reconstruct the process-local recovery/launch/guard objects behind it.

`--verify` and `--require-no-active-caps` fail closed on partial inventory, stale
native proof, pending intents, external control conflicts, unknown Job state,
unresolved cleanup or unavailable authorized owner. Complete paged historical
validation uses a stable revision/cursor. Ten concurrently managed Jobs does
not mean reading only ten history rows proves completeness.

Report proof provenance separately: current native readback for retained live
scope versus exact validated terminal retirement evidence for an already
retired scope. Never relabel a ledger-only result as an OS query. Audit is a
bounded observation at its stated binding/revision; a stable rollback claim
additionally requires the acknowledged freeze/drain so no normal writer may
immediately reapply a cap. No-active-caps does not mean Job empty, allocation
released, infrastructure exited, or binary rollback safe.

Operational exit codes are fixed as follows:

| Exit code | Outcome |
| --- | --- |
| `0` | This command's complete success condition is verified |
| `2` | Refused request or invalid/unauthorized operation |
| `3` | Accepted but pending/draining, including a bounded wait ending with a known pending result |
| `4` | Required discovery, ledger, endpoint or supported authority unavailable before an uncertain mutation |
| `5` | Outcome unknown/unverified, including possible mutation delivery without an authenticated conclusive result |
| `130` | Observer interrupted; the owner operation continues independently |

These codes apply to operational commands, not a successfully executed
workload. `run-managed` retains the actual child exit code and the existing
separately typed infrastructure-refusal records/codes. Never reinterpret a child
exit `3`, `4`, `5` or `130` as an operational result without the associated typed
record. Interrupted observers return control without cancelling owner work or
forging a final result. An unavailable transport after possible delivery uses
unknown `5`, not a clean unavailable `4`.

## 8. Implementation sequence and ownership

1. Integrate original-context RESERVED/queued/named-scope abandonment and wrapper
   failure/interrupt ownership. Add exact replay and no-release-on-unknown tests.
2. Integrate FINISHED native custody retirement, applicable barrier settlement
   and partial-cleanup retry. Demonstrate a completed execution actually leaves
   retained inventory, while children/unknown cleanup still prevent exit.
3. Implement descriptor validation/publication and separate typed operational
   service/client with native peer binding. Verify all refusal paths before
   exposing host mutations.
4. Wire guardian, helper and supervisor drain/recover/audit state. Demonstrate
   intentional child exit never causes replacement and failed recovery remains
   actively retained, with no normal-policy restart.
5. Add a dedicated operational CLI module and narrow dispatch/parser hunks in
   `scripts/sentinelctl.py`; preserve its pre-task attribution/wait-reporting
   changes. Add command help and runbook evidence, then run affected/full tests.

Keep source ownership disjoint: release/launcher/wrapper and their tests;
terminal lifecycle/control cleanup and tests; discovery/contracts/transport and
tests; host integration; CLI/documentation. The coordinator assigning work owns
shared host files. Do not have multiple workers independently alter failure
cleanup ordering in the same host.

## 9. Required verification and remaining gates

Portable tests use isolated real SQLite/journals plus explicitly synthetic
process/Job/pipe/mutex adapters. They must cover:

- missing/read-only/incompatible DB: status/audit make no file, migration or
  control write; existing legacy CLI behavior and managed-row protection remain;
- queued cancellation, exact RESERVED archive, another owner/reservation,
  duplicate commands, lost admission ACK, Prepare/claim boundaries and same-ID
  retirement replay; no caller-supplied native proof or fresh-context recovery;
- root exit with live grandchild, unknown Create/Bind, failure/interrupt during
  each release/cleanup boundary, and no silent normal exit with sole custody;
- FINISHED with and without prior control episode, pending barrier, failed clear,
  terminal archive contradiction, and complete/partial/unknown native close;
- exact discovery replacement, stale descriptor, PID reuse, foreign logon,
  malformed/big message, unknown protocol, changed epoch and retained peer death;
- operator/helper privilege separation, mismatched request replay, delivery/ACK
  uncertainty, and mutation outcome independent of CLI disconnection;
- mode-off with a cap, pending intent or unavailable DB; native restore state
  separate from bookkeeping; live jobs retain allocation and legacy exclusion;
- atomic off/HOLD CAS, no-op without revision inflation, wrong instance/epoch,
  stale revision, lost commit acknowledgement, exact request replay, original
  guard retry and unknown cleanup quarantine; preexisting/no-slot HOLD remains;
- guardian/helper normal exit during intentional drain, death during drain,
  cleanup retry with exhausted restart budget, cold restart HOLD and zero new
  child creation from an accepted stop;
- audit refusing incomplete inventory and unknown cap state; no-active-caps
  never becoming all-work-finished; complete stdout/stderr/exit compatibility.

Native tests additionally require supported-host capability, isolated owned
processes/endpoints, real peer/PID-reuse checks, Job containment, restored CPU
readback, launch/stdio/exit compatibility and full drain/recovery observation.
Do not use the user's workloads as crash, kill or cap fixtures. Existing P1
S1-S3, P4 overhead, P5 fault recovery and P6 A/B gates remain necessary. A CLI
wrapper around an unimplemented authority path is an honest refusal, not gate
completion. Record blocked/unverified native cases without mock/skip promotion.

## 10. Selected integration choices and remaining limits

The previously open implementation choices are resolved:

1. Discovery uses the explicit target's `adaptive-host` protected namespace;
   supervisor canonical instance publication and exact child-bound guardian
   ready metadata. Direct guardian launch remains explicit-endpoint-only.
2. Supervisor coordinates full drain. Default is one bounded RPC; `--wait` is a
   bounded observer of the same operation and cannot change owner semantics.
3. Operational exits are `0/2/3/4/5/130` as specified in section 7; managed child
   exits and typed infrastructure refusals preserve the wrapper contract.
4. New host-owned `FencedOffOperation` uses the existing retained POLICY adapter
   and the exact conditional transaction in section 6. It writes no daily
   configuration and adds no new native restore or cold-adoption authority.

The no-slot HOLD limitation documented in section 6 remains a concrete recovery
case to report and test. It is not permission to add an unchecked barrier-clear
path or to claim instance-wide rollback complete while the hold is unresolved.

Cold recovery without a valid retained witness remains unsupported by design.
If operational requirements later require prospective ALIVE adoption or a new
external recovery authority, stop promotion and amend C4 with concrete native
evidence; do not smuggle it into discovery, `--verify`, or this CLI contract.
