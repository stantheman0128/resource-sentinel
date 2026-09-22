# Helper control integration contract

Date: 2026-09-22. Status: **implementation contract; no native gate or promotion**.
The current progress index remains [README.md](README.md). This contract closes
goal item 3's interface decisions; it does not change daily configuration,
Scheduled Tasks, admission policy, enrollment limits or capability verdicts.

Authority: [IMPLEMENTATION-PLAN.md](IMPLEMENTATION-PLAN.md) §§3.1–3.3, 5.4–5.5,
6.1–6.5, 7.1–7.5, 8.3–8.4, 9 and 13.2. The accepted helper authentication
clarification in README decision ③ continues to apply: the unique registered
helper's OS-verified peer identity plus a request-bound server nonce, without a
new shared secret. [C4](P3-SUPERVISOR-FAILSAFE.md) remains responsible for
supervisor recovery; a helper restart is not a new actuator or recovery owner.

## Ownership and existing interfaces

| Implementation owner | Files / existing API | Required boundary |
| --- | --- | --- |
| Transport and contracts | `contracts.py`, `control_transport.py`; `ControlProposalClient.propose`, `ControlProposalService.serve_once` | Typed bounded messages, peer authentication, response correlation and outcome uncertainty; no policy or native Set. |
| Guardian consumer | `guardian_control.py`, `guardian_host.py`; `apply`, `request_restore`, `observe_uncapped`, both barrier-clear methods, `_control_rpc` | Validate authoritative bindings, own cap transitions/readback and recovery; only normal actuator. Coordinate edits with C4 host work. |
| Helper sender | New `helper_control.py` and explicit host wiring; reuse `FrameSampler`, `next_state`, `build_control_proposal` | One pending operation, one victim, ACK-driven execution state, query-only Job access; default shadow does not construct a control client. |
| Pure policy | `decision.py`; `Decision`, `DecisionAction`, `ControllerSnapshot`, `ActiveIntervention`, `next_state` | Propose the plan's two retreat levels and stepped normal recovery; no transport, native mutation or capacity release. |

Endpoint discovery and operational mode/stop CLI belong to goal item 4. The
sender accepts a pinned `NativePipeEndpoint` from that mechanism; arbitrary PID
or Job-name control is never an alternative. Existing `helper.py` stays a pure
shadow observer. A separate active driver may reuse its bounded sampling
components without converting a would-apply record into authority.

## Control pipe API

Keep `ControlProposal` and `ApplyAck` fields required by plan §13.2. Keep
`ControlProposalClient.propose(proposal, *, timeout_ms=1000) -> ApplyAck` and its
single-attempt semantics. Add the following typed operations to the same
authenticated service; these names are the agreed implementation interfaces:

```text
ControlProposalClient.observe_uncapped(
    frame: FastFrame, *, request_id, guardian_epoch, policy_epoch,
    timeout_ms=1000) -> ControlFrameAck

ControlProposalClient.request_restore(
    execution_id, *, request_id, guardian_epoch, policy_epoch, reason,
    timeout_ms=1000) -> RestoreAck
```

All envelopes carry protocol `version`, closed `kind`, canonical UUID
`request_id`, `guardian_epoch` and `policy_epoch`. Frame messages use kind
`ControlFrameRequest` and contain exactly one typed `FastFrame`; restore uses
`ControlRestoreRequest` with canonical `execution_id` and a bounded stable
`reason`. They accept no raw command, PID, Job name, limit class or force flag.
The existing proposal envelope remains `ControlProposalRequest`.

`ControlFrameAck` carries the common request/epoch binding, `sampler_epoch`,
`clock_epoch`, `sample_seq`, authoritative `registry_revision`, `config_revision`,
and a bounded tuple of per-execution results. Each result carries
`execution_id`, `observation` (`UNCAPPED`, `CAPPED`, `REJECTED`, `UNVERIFIED`),
`queried_tick_100ns` or null, `barrier_cleared` and a stable reason. This ACK is
neither an applied-cap acknowledgement nor proof that admission capacity was
released. At most ten results may appear; a missing result is unknown.

`RestoreAck` carries the common request/epoch binding, `execution_id`,
`result` (`RESTORED`, `REJECTED`, `UNVERIFIED`), `native_disabled`,
`bookkeeping_settled`, `slot_released`, `barrier_cleared`, native
`applied_flags`/`applied_rate_bp` and `applied_validity`,
`queried_tick_100ns`, `reason`, and `win32_error` or null. Unknown observations
remain null/unknown. `RESTORED` requires disabled native readback and settled
bookkeeping/slot obligations; an unfinished admission barrier is reported
separately. `request_restore()` currently returning `None` or an internal
`RestoreResult` is not by itself enough to build this ACK: obtain native readback
and report each obligation. Absence of an episode never proves disabled.

The existing challenge binds endpoint instance, both exact identities,
request ID and guardian epoch. Extend it to bind the operation kind and policy
epoch for the new operations. Authenticate the unique registered helper before
reading request bytes; verify both peers around the owner call and response.
Use existing strict JSON, protocol-major, 256 KiB and total-deadline bounds.
No per-operation unbounded queue, retry loop or fresh nonce may hide an
uncertain previous operation. Duplicate requests with different payloads refuse.

One frame RPC conveys all at-most-ten aggregates. The guardian caches at most
the latest validated frame for this exact helper/session binding. Capped Job
aggregates may be cached as frame references for renewals, but must return
`CAPPED` and never enter the uncapped sample buffer. For each eligible uncapped
aggregate, call the existing `GuardianControl.observe_uncapped(execution_id,
frame)` so the guardian obtains its own disabled Query. Replaying a frame does
not add another sample or advance warmup/barrier streaks. Cache no private
process lists or raw command content.

The guardian attempts `clear_admission_barrier()` after sufficient distinct,
fresh, post-restore observations. Independently, its lifecycle loop retries
`clear_finished_admission_barrier()` for its finished retained scope using the
existing exact empty/disabled/settled evidence. Finished scopes need not remain
enrolled in the helper to be cleared. Do not expose a force-clear RPC.

During drain/off, continue servicing restoration and necessary observations;
reject cap creation, target changes and renewal. `_control_rpc` must dispatch
the typed response union rather than assuming every response is `ApplyAck`.
RPC/frame work remains bounded so it cannot starve guardian lease sweeps.

## Authoritative binding and capability

Before proposing or applying restrictions, bind all of the following:

- The guardian endpoint's exact process identity, instance and guardian epoch;
  current retained execution/Job custody and the POLICY instance epoch.
- Durable `adaptive_runtime.registry_revision`. `FrameSampler.registry_revision`
  currently counts local enroll/release operations and is **not** this value.
  Keep local enrollment generation separate; bind a frame to a consistent
  authoritative registry snapshot covering its enrolled identities. A changed
  snapshot invalidates the frame for control rather than relabeling old data.
- `config_revision` of the agreed validated policy profile. Helper and guardian
  use the same revision; deriving an in-memory enforce decision profile must
  not silently substitute a different hash for the advertised profile.
- Exact registered helper identity, sampler epoch, clock epoch and fresh sample
  sequence. Guardian independently checks its interrupt-time window, continuity
  and resets. A clock/sampler restart cannot preserve the old baseline or extend
  an old lease. Initial synchronization requires disabled inventory and warmup;
  do not compare unrelated process-local epoch labels as if equal meant proof.
- CPU denominator from current native host capability, matching the frame,
  target and measured capability evidence. Host build/topology/affinity/parent
  Job changes invalidate eligibility and require restoration/reprobe.

Capability evidence must reference actual successful required native results
and their code/profile/host scope; S1 API/effect/restore evidence is necessary,
and subsequent P5/P6 gates govern promotion. A boolean, JSON `supported=true`,
successful preflight, synthetic test, skipped test or writable mode value is
not capability evidence. Both the helper eligibility source and guardian's
final restriction check must enforce this. Missing evidence permits shadow
only, and remains an explicit blocker in the progress index. Isolated spike
execution uses its own established test authority; it does not bootstrap a
production allowlist by asserting the result it is meant to measure.

Frame publication does not replace guardian's fresh exemption authority read,
scope check, writer exclusion, lifecycle/allocation proof or POLICY transaction.
Restore is not gated on fresh sampler/config/capability proof: authenticated
requests restore only the exact retained owned episode through its existing
recovery fence. Stale global revisions are not permission to skip that recovery.

## Sender state and outcome uncertainty

Default adaptive mode remains `off`; the observation entrypoint runs only
explicit `shadow`. Off/shadow construct no cap sender and emit no restrictive
proposal/renewal or native Set. An explicitly enabled isolated control driver
requires the authority and gates above; a profile-file string alone cannot
enable it. Leaving active mode still permits restoration of a pre-existing cap.

Keep one pending request with its exact immutable payload, one sequence stream
per bound episode and one acknowledged active target. Build a proposal only
from the same tick's validated frame and decision. A gap must not reuse
`ShadowHelper.latest_frame` from an earlier successful tick. Renewal references
the acknowledged applied target, not a newly calculated or merely proposed one.

Only a correctly bound, valid, unexpired `APPLIED`/`RENEWED` ACK advances applied
state. A replayed historical ACK does not establish current native inventory or
restart an expired lease. A lost/partial write, timeout after send, peer change,
UNVERIFIED response or inconsistent ACK retains uncertainty: no new victim,
fresh request ID masquerading as retry, new tightening or capacity release.
Reconcile the same operation or request restore. The guardian's independent
lease sweep remains the fallback. A proposed restore does not put the driver
into verified cooldown/off until its restore outcome is verified.

## Target changes, recovery and demand floors

Under the existing POLICY -> per-Job fence and retained ownership, a changed
target on the same episode is a new journaled action, not a renewal: compare
actual current control with the owned state; preserve the original recovery
control; durable intent -> Set -> Query -> settle manifest -> ACK -> batched
audit. Preserve original slot, victim, intervention deadline and baseline.
Unknown/conflicting state restores or holds; it never overwrites foreign state.
Pure same-target renewal performs Query and extends only the valid bounded
lease, with no Set or per-second manifest fsync (plan §§8.4 and 13.2).

Implement normal L1 -> L2 after the plan's persistent-high condition and normal
recovery L2 -> L1 -> original baseline ceiling -> disabled. Normal target changes
are at least five seconds apart; the original intervention deadline always wins.
Grant/fault/mode-off/lease-expiry restoration goes directly to disabled and does
not wait for those steps. CPU in the 80–90 percent band is not another high
sample. Reconcile the step's ACK before proposing its successor.

The pure decision interface adds `DecisionAction.PROPOSE_BASELINE`.
L2 -> L1 uses `PROPOSE_L1` with reason `recovery_level_1`; the next upward
step uses `PROPOSE_BASELINE` with reason `recovery_baseline`.
`ActiveIntervention.level=0` represents the original baseline ceiling during
recovery; it is not a third retreat level or a zero CPU target. Preserve the
original `baseline_cpu_units`, `started_tick_100ns` and `deadline_tick_100ns`.
Keep CAPPED_L1/L2 during low-pressure qualification; enter RECOVERING when the
first outward target is proposed and continue outward even if CPU rises.
The helper ACK gate distinguishes this proposed snapshot from applied state.
If the baseline is at or above N, it cannot form an effective cap: after the
ordinary step interval, proceed to disabled rather than inventing a rate.
`proposal_builder` must recognize the new action without permitting shadow
would-apply records or arbitrary targets to become executable proposals.

Before the first cap and every target transition, retain/update the lifetime
high-water allocation using validated actual measurements and include that
floor in the durable recovery intent. A lower capped measurement never lowers
the floor or admits another job. Missing private memory attribution deducts
zero; requested demand and existing floors remain. Frame/ACK delivery never
releases a reservation; only the existing lifecycle/restore/barrier contracts
can do so (plan §§7.1–7.4).

## Corrections to existing partial implementations

These are completion of the formal plan, not permission to relax it:

1. `GuardianControl._renew_locked` currently rejects every changed target;
   replace that missing transition with the journaled path above.
2. `decision._active_tick` currently jumps to disabled after low-pressure dwell;
   implement the specified normal stepped recovery. Fault restore stays direct.
3. Local enrollment revisions and assumed helper capability currently cannot
   satisfy authoritative control bindings; integrate real sources, not constants.
4. Uncapped/finished barrier methods and restore lack production transport/host
   callers; connect them without weakening their native evidence checks.

Portable verification must exercise sender -> transport -> real guardian consumer
-> restore -> fresh uncapped observations -> barrier clear, with explicitly
synthetic native collaborators. Include peer-before-read, payload/ACK mismatch,
duplicate/lost ACK, epoch/revision changes, fixed deadline/slot across target
changes, stepped recovery, capped-frame exclusion, finished-Job retry and zero
shadow writes. Preserve query-only helper handles. Any structural test whose
old wording forbids all guardian communication must continue proving zero
restrictive shadow behavior; do not delete safety coverage to enable a sender.
Native effect, timing, overhead and A/B remain separately unverified until the
required isolated measurements exist. This document reports no test passes.
