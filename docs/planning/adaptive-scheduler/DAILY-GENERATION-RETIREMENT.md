# Positive retirement of the daily accounting keeper

This is the implementation contract for an explicitly requested retirement of
the original `DailyActivationHost`. It does not authorize daily installation or
retirement during implementation, and it does not enable adaptive control.

Ordinary CPU-control drain and daily-generation retirement are different
operations. Ctrl+C requests ordinary drain. An explicit retirement request on
the original host object records intention only; no CLI flag, JSON document,
live PID or database state is a native-cleanup receipt.

## Freeze before drain

One retained operation binds a preminted request UUID to the exact original
generation owner, source/configuration digests, ledger file identity, readiness
instance and existing POLICY guard. Under that guard and one short transaction,
it installs a schema-versioned `adaptive_daily_retirement` admission freeze.
The generation remains `ACTIVE` while restoration and accounting cleanup run.
Changing it to `DRAINING` at this point would prevent those operations and even
prevent the original POLICY nonce from being cleared.

Coordinator and Maintainer check the freeze inside the admission transaction,
before new allocation **and existing-reservation reuse**. Managed enrollment,
new launch claims and experiment admission do the same. Additive SQL guards
also fence already prepared connections. The freeze does not authorize any
writer; all existing source-generation, POLICY, capacity and lifecycle checks
still apply. Existing heartbeat, conservative demand-floor increases, recovery
of already issued launches, terminal proof, release and user exemption storage
remain possible. No grant is issued, renewed, revoked or deleted by retirement.
Pending queue records remain evidence; retirement does not cancel them.

After positive freeze acknowledgement the original supervisor performs its
existing off/drain operation. Retirement does not invent a second recovery HOLD
or infer that a mode change restored an OS limit. The frozen state remains even
if ordinary recovery later clears its own barrier. New tightening is prevented
by the existing off operation and by the retirement pre-effect guard.

## Positive settlement and final seal

The original operation retains all SQL, POLICY, source, process, cohort and
readiness owners while drain progresses. It requires all of the following:

- The original supervisor has completed its retained drain, including native
  restriction restoration, Job-empty observations, infrastructure retirement
  and positive native-handle cleanup. Its public status record alone is not
  authority.
- No direct or routed reservation remains. Every managed execution, including
  historical terminal rows, has its applicable immutable custody receipt;
  absence of a reservation, TTL expiry or root exit is insufficient.
- The manifest/intent inventory agrees with the ledger and exact positive
  terminal receipts. Unknown, orphan, malformed, extra or unsupported history
  blocks retirement. Nothing is deleted to make this inventory empty.
- No live cap/control slot, unresolved recovery barrier, infrastructure registry
  owner or exclusion obligation remains. Supplemental writer-obligation checks
  cannot replace the complete native and accounting proof.
- Experiment-demand metadata has an implemented, exact positive native-cleanup
  retirement receipt. The first experiment schema only records admission, so
  **every row currently blocks retirement**. An unknown schema also blocks it.
- All original SQL connections and POLICY operations have known outcomes.
  Unknown commit, rollback or close retains the original owner; retrying an
  unrelated connection is not proof that an uncertain close succeeded.

Inventory preparation may happen outside a transaction. The final original
POLICY transaction rechecks its exact frozen request and the complete ledger
inventory/receipts before changing the generation to `DRAINING` and persisting
the immutable seal. Only this original seal operation may open a lifecycle
connection that clears its exact POLICY nonce. That connection receives a
nonce-only SQLite authorizer and no capacity-generation function. A different
request, connection role or nonce cannot use that path.

The seal is acknowledged only after original transaction, POLICY and connection
cleanup and separate bound readback. Then the same readiness thread stops,
joins and positively closes its original listener/registry; the retained cohort
and current-process handles close last. Unknown cleanup stays resident. Only
the complete original operation may allow `run_forever()` to return normally.

## Meaning of clean exit and restart gap

A clean retirement **leaves daily admission fenced**. It is not a return to
admission-only service. Generation triggers, additive schema, queue, exemptions
and all lifecycle history remain. Neither feature off nor keeper exit enables
legacy writers. There is no automatic rollback of the ledger or source.

A fresh generation after positive retirement needs its own explicit transition:
verify the predecessor's immutable retirement/custody evidence and source and
ledger bindings, capture a fresh original native owner and cohort, preserve all
history, atomically replace the generation under the existing POLICY, and start
authenticated readiness before accepting capacity. ACTIVE or uncertain old
generations must never be cold-adopted. This restart transition is presently an
implementation gap; the activation command must not be advertised as reusable
after retirement until that path and its native recovery evidence exist.

## Verification and monitoring cost

Unit tests must exercise replay fencing, already prepared SQL writers, allowed
cleanup, managed-history/experiment blockers, exact original seal authority,
ACK loss and each retained-close uncertainty. They are not Windows evidence.
Native activation, recovery and retirement must use separately authorized daily
handoff plus isolated native fixtures. They have not been run by this change.

P4 must charge the generation keeper/readiness thread and repeated source/import
verification to monitoring cost. A one-second RPC deadline is not proof that
full-source verification meets that deadline. A future optimization needs an
original retained-source proof; mtime-only caching is insufficient.
