# Daily readiness transaction boundary decision

Status: contract correction explicitly approved by the user on 2026-09-25;
implementation remains pending. The user then requested wrap-up and a pause.
No runtime change or promotion is authorized by this document. Baseline: `b9132cc`.

## Observed contradiction

The formal IMPLEMENTATION-PLAN.md requires OS identity observations outside the
transaction (P2, line 826); section 7's lock order text also puts identity and
telemetry before the short transaction. The later
DAILY-READINESS-LOCK-BOUNDARY.md requires `observe()` and filesystem/config/source
revalidation at each capacity UDF write, including changes after BEGIN. Its
current tests deliberately reject a peer that dies after BEGIN. Meanwhile
S1-DAILY-BRIDGE-CONTRACT.md forbids any transaction spanning a native query.

The actual shared path is PolicyCoordinator.prepare ->
LifecycleStore._transaction -> daily_generation.revalidate_transaction ->
SELECT sentinel_daily_generation(). The installed UDF calls filesystem/source
checks and DailyReadinessAuthority.revalidate -> peer.observe(). The same issue
exists in absence and nonce-clear checks that resolve/stat paths inside SQL.
Passing portable tests cannot establish that this boundary is correct.

## Approved correction, not yet implemented

Use the formal plan's observation boundary for SQL bookkeeping, without making
an admitted reservation sufficient authority to create or restrict work:

1. Before each consumer BEGIN, while retaining the original lexical readiness
   owner, validate original native peer and exact ledger/config/source/import
   provenance. No new RPC, replacement peer, refreshed deadline, or different
   generation may be acquired under POLICY/Job.
2. Bind this exact connection to the complete observed generation, original
   owner/peer/backend/handle/deadline and scope identities. Inside BEGIN and at
   each capacity trigger, compare only the same SQLite connection's complete
   generation/state, its already-bound database metadata, and retained in-process
   identities/closed/poison state and deadline. Never perform filesystem or
   process queries there. A copied tuple or boolean is not a readiness factory.
3. The original <=1,000 ms remote deadline never renews. A conservative local
   monotonic bound may be captured before querying original remaining time, so
   conversion cannot extend it. Clock discontinuity or expiry fails closed.
4. After SQL closes and immediately before every Create/Set, repeat actual
   native/source/file validation from the same original authority and carry its
   original deadline to the concrete native call. Ordinary admission must not
   bypass its existing launch/lifecycle gates. Restore retains its separate
   original-native recovery authority and does not require new daily readiness.
5. Keep intent charged if readiness fails after reservation. Root exit, expiry,
   handle close, feature off, or a failed observation never prove children empty
   or release capacity. Unknown SQL/native cleanup retains the original owner.
6. Preserve nonce-only cleanup permissions. Its connection is validated before
   BEGIN; its locked trigger checks exact original guard, released ownership and
   unchanged SQLite row. It cannot become a capacity or DDL bypass.

## Accepted semantic difference

This changes the later document's per-write observation guarantee. A peer death
or filesystem change occurring after the final pre-BEGIN observation is not
queried inside that SQL transaction. The transaction may conservatively record
an intent, but that intent must never enable native work without a new actual
post-SQL validation. Do not describe the revised behavior as unchanged per-write
liveness, silently change the old tests, or declare promotion passed.

The user selected the formal-plan boundary above, accepting this observation
timing change while retaining the complete gate verification. The old per-write
native tests must be updated explicitly with regression coverage for the new
semantics, not silently removed. Current source still uses the old observation
timing; native promotion remains blocked until the correction and caller gates
are implemented and verified. Exact original-handle hardening is independent.

Coverage includes ordinary remote/local capacity, absent generation, nonce-only
cleanup, daily successor and experiment cleanup/release. Both successor/cleanup
dispatch helpers also resolve paths; checking only the principal capacity UDF
would leave actual transaction-time filesystem probes. No changes to those
shared files or new transaction-boundary tests were made before the pause.

## Required evidence before promotion

- Real isolated SQLite traces for ordinary Coordinator, Maintainer, POLICY
  prepare/hold/clear, absent generation, local/remote owners and legacy writer.
- Spies fail on native/file/source probes whenever the actual connection is in
  transaction; metadata/pins/deadline changes still reject before mutation.
- A peer dying or source changing after BEGIN cannot reach any native Create or
  Set, retains capacity, and does not refresh an authority. Expected SQL-only
  intent behavior is tested explicitly against the approved decision.
- Preserve existing rollback, close-unknown, nonce-only, expiry and retirement
  tests; record any intentionally changed assertion and the decision authorizing
  it. Native provider acceptance remains separate and unverified.
