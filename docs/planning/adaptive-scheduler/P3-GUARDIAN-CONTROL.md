# P3 guardian control consumer

The guardian-side consumer of `ControlProposal`. It is the actuator that applies
a Windows Job Object CPU rate cap, keeps a lease on it, restores it, and clears
the admission barrier once the restore is proven. The helper decides and
proposes; it has no Set path, and neither does the supervisor or the wrapper.

Code: `sentinel/adaptive/guardian_control.py`, with additive support in
`sentinel/adaptive/control_slot.py` and `sentinel/adaptive/store.py`. Tests:
`tests/test_adaptive_guardian_control.py`.

## What the consumer does

`GuardianControl` wraps one `GuardianLaunchOwner`. It exposes five operations:

- `apply(proposal)` consumes one proposal and returns one `ApplyAck`.
- `tick(now)` sweeps for expired leases, a reached intervention deadline, a
  ledger mode that left canary or limited, and newly granted exemptions.
- `request_restore(execution_id)` withdraws a cap on demand.
- `observe_uncapped(execution_id, frame)` records one post-restore sample.
- `clear_admission_barrier(execution_id)` attempts the `RECOVERY_HOLD -> NONE`
  transition.

A proposal is a request, never an authorization. Every fact it carries is
re-proven here, under POLICY, against the authority that owns that fact.

### Apply order

Plan section 8.3 fixes the order, and the recovery journal's own
`_control_transition` enforces it independently:

1. Reserve the control slot. This is the at-most-one-capped-Job rule and the
   `NONE -> CONTROLLING` barrier transition.
2. Publish the durable recovery intent. A failure here means no Set happens.
3. Native Set through `set_cpu_rate_unverified`, the Set boundary that
   deliberately does not acknowledge itself.
4. Native Query. A failed or mismatched readback never produces an applied
   acknowledgement; it forces compare-and-restore.
5. Publish the settled manifest recording what the Query actually returned.
6. Return the `ApplyAck`.
7. One batched audit commit into `adaptive_actions`.

The test `test_apply_orders_intent_then_set_then_query_then_ack_then_audit`
asserts this sequence twice over. The first assertion reads the consumer's own
call log. The second reads two recorders the code under test never writes to:
the synthetic Job's own list of Set, disable and Query calls, and a wrapper the
test installs around the real journal `publish`. A native Set the consumer
forgot to log, or one issued before the durable intent, fails that second
assertion.

A fault at any step after the native Set ends in compare-and-restore, and that
includes a failure to publish the settled manifest at step 5. The acknowledgement
is then `UNVERIFIED` with reason `control_settle_failed`, the cap is withdrawn,
and no `APPLIED` row reaches `adaptive_actions`. If the withdrawal also fails
because the journal is still unwritable, the episode keeps no lease, so the next
`tick(now)` retries the restore. A later proposal for that episode is refused as
`control_episode_unverified` instead of being renewed, because a cap that was
never verified and durably settled is never acknowledged or extended.

### Lock order

Plan section 7.5: the existing `PolicyCoordinator` first, then the lifecycle's
per-Job mutation scope, then one short SQLite transaction inside it. Both come
from `GuardianLifecycle._scope`, which is reentrant for the same entry and
thread, so the nested evidence provider does not take a second lock. No new lock
is introduced.

### Lease

The lease is the guardian's, not the proposer's. It comes from the existing plan
13.2 formula in `decision.lease_deadline_tick`:

    lease = min(now + lease_ms, sample_window_end + lease_ms, intervention_deadline)

`intervention_deadline` is `proposal.decision_tick_100ns + intervention_max_ms`,
fixed when the episode starts and immutable afterwards. A renewal recomputes the
lease against that same original deadline, so it can never outlive it.

A retry at the same decision sequence returns the original acknowledgement
object and extends nothing. The same sequence arriving under a different request
id is refused as `decision_seq_replayed`. An older sequence is refused as
`decision_seq_stale`.

## Evidence behind each refusal and transition

| Fact | Authority |
| --- | --- |
| Ledger mode is canary or limited | `adaptive_runtime.mode` read through `PolicyCoordinator.revalidate` under POLICY, and independently again inside `control_slot.begin_locked` |
| Barrier and slot state | `control_slot.begin_locked` compare-and-swap on `adaptive_runtime` and `adaptive_control_slot` |
| Role, priority, coverage, launch seal | the `managed_executions` row read under POLICY, checked in `_eligible` and again in `begin_locked` |
| Legacy CPU, I/O and trim writer exclusion | the host collaborator's `assert_excluded(row)`, reached through `GuardianLaunchOwner._authority`, which treats any non-`None` return as unverified |
| User exemption state | `exemption_sync.snapshot_locked` re-read under POLICY, joined to the scope evaluator; anything other than `UNRELATED` refuses, and an unreadable authority refuses |
| Accounting reconciled | `sentinel/accounting.py` `validate_active_allocation`, wrapped by `LifecycleStore._require_allocation`, plus the composite `assert_retained_allocation` that `GuardianLifecycle._manifest` runs |
| Native custody and current cap | `GuardianLifecycle._control`, `_members` and `_manifest` inside the retained evidence scope |
| Durable recovery record | the formal `RecoveryJournal`, whose `_control_transition` validates every intent and settlement against a live Query |
| Fresh uncapped samples | `UncappedSample` rows, each pairing one `FastFrame` with this guardian's own disabled Query, validated by `control_slot._uncapped_samples` |
| Restore boundary | the latest `adaptive_actions` row for the execution, which must be `RESTORED` with a real applied tick |

Exemptions are only ever read. Nothing in this consumer grants, extends, revokes
or ignores one, and no code path here can change a ledger mode.

Under ledger mode `off` or `shadow` no cap is ever applied and no lease is ever
renewed. A controller holding no open episode never touches the Job at all. A
cap already held when the mode leaves `canary` or `limited` is a separate case:
it is withdrawn through compare-and-restore, and that withdrawal is one native
`disable`. The restore direction stays available in every mode, because leaving
a cap in place because the mode changed would be the unsafe reading.

## Restore

Lease expiry, a reached intervention deadline, `request_restore`, a granted
exemption, a mode leaving canary or limited, and any fault all end the episode
the same way: `GuardianRestorer.locked`, which is the existing plan 8.4
compare-and-restore. It compares the observed control against the manifest
candidates, disables only its own cap, publishes a settled manifest, then calls
`release_control_slot_locked`, which leaves the barrier in `RECOVERY_HOLD`.

`tick(now)` performs lease-expiry restore without any helper message, so a
silent helper cannot leave a cap in place.

A capped Job's reduced CPU is never written anywhere as released capacity. The
audit ledger records flags, rates and ticks; it holds no capacity column, and
the allocation floors are untouched by every path in this module.

## Barrier clear

`clear_recovery_hold_locked` performs one compare-and-swap from `RECOVERY_HOLD`
to `NONE`, guarded on the exact `registry_revision`. It requires all of:

- the slot row is `RESTORED` and bound to this exact execution;
- the retained evidence scope shows a current disabled Query and a settled
  durable manifest;
- the store's existing allocation validation passes;
- the durable action ledger's newest row for this execution is `RESTORED` with a
  real applied tick, which is also the proof that no later intent is unsettled;
- the configured count of uncapped samples, `admission_release_uncapped_samples`
  with a default of 5, all observed after that restore tick, strictly increasing
  in sequence and window, each fresh when observed, with the newest still fresh
  now.

Samples taken while capped are impossible to record: `observe_uncapped` queries
the guardian's own Job first and refuses when a cap is present. A usage drop on
its own counts for nothing. There is no TTL, no force flag and no operator
bypass. Anything missing raises and the barrier stays.

Acquiring a new cap bumps `registry_revision`, so conditioning the swap on the
expected revision also rules out any cap having existed during the sampled
window.

## What is synthetic

In `tests/test_adaptive_guardian_control.py` the store, the control slot, the
policy coordinator, the recovery journal and the exemption ledger are the
production modules against real temporary SQLite files and real journal files.
The Job, the processes, the mutexes, the host authority and the grant scope
evaluator are explicitly labelled in-process fixtures. The Job answers queries
and counts every Set, and it records its own call order for the tests that check
what the consumer actually did to a Job. It contains nothing and kills nothing.

Every ledger mode write in that module is a fixture write into an isolated test
database, marked as such at each site.

## What is not delivered

- No host process wires this consumer to anything. There is no thread, no
  scheduled task, no CLI entry point and no service that calls `apply` or
  `tick`.
- No native evidence on a supported host. `require_supported_host()` refuses
  this machine because of a foreign parent Job, so nothing here has driven a
  real Job Object.
- No measured timing. The lease and intervention values are configuration. A
  configured one second or six second timer is not evidence of a measured
  reaction or restore time, and no plan 11.2 threshold is claimed.
- Mode promotion is not implemented and is out of scope. Nothing here can move
  the ledger out of `off`.
- Changing the target of an existing cap is refused as
  `control_target_change_unsupported`. Escalation between control levels is not
  defined here.
- A terminal execution cannot clear the barrier. The clear needs an active
  allocation, and a finished Job produces no uncapped samples. That case fails
  closed. If the capped Job finishes before the required samples exist, or its
  guardian dies and the orphan drain finishes it, the barrier stays
  `RECOVERY_HOLD` and keeps refusing new non-exempt admissions. Plan section 7.4
  does not say whose samples count once the Job is gone. That is a plan
  clarification for the repository owner, listed in `ACCEPTANCE-RESULTS.md`.
  Nothing here relaxes the rule to get past it.
- The default grant scope evaluator proves nothing. It answers `UNKNOWN` for
  every lease it is shown, so a proposal is refused as `exemption_scope_unknown`
  whenever at least one active exemption lease exists. With no active lease
  there is nothing to evaluate and the proposal carries on to the other checks.
  A real deployment must supply an evaluator backed by native process and job
  membership evidence before any grant can be proven unrelated to a capped Job.
