# Original experiment scope with remote daily readiness

Status: contract before implementation, following `90e1b1b`. This connects the
existing authenticated readiness authority to the original experiment scope.
It adds no transport, remote owner adoption, provider activation or native gate.
Production adaptive remains off. The 58/4/4/3 policy and original lifetimes stay.

## One existing lexical owner

The experiment already pre-acquires daily and isolated readiness owners before
the daily POLICY -> isolated POLICY -> Job locks. Its `_ready()` currently
requires `_LOCAL_GENERATIONS`, even though an actual remote authority can now
be retained outside those locks. Replace that local-only dependency with:

`daily_generation.revalidate_scoped_readiness(db_path, *, expected_generation)`

This helper only selects an already-acquired exact single scope or group member;
it never opens a scope, SQL connection, RPC, process handle or replacement owner.
Restore the prior ambient selector on every outcome. Require the exact retained
scope/registry/thread, no poison/close/cleanup marker, ACTIVE present generation,
original ledger/file identity and full original generation row. Absence-only
and cleanup scopes cannot authorize new native work. Compare every field to
`demand._original_generation_binding()`, not just generation/source/config.

Preserve source/import, file/location and fixed config checks. Validate the
original remote authority before and after those local checks without RPC.
Pin a local owner during the same pre-lock proof that calls its `assert_ready`;
later checks use that original object with `_revalidate_local`, never SQL-opening
`assert_ready` under locks or a new registry lookup as adoption authority. An
originally remote scope cannot switch to a subsequently registered local owner.

The helper may return only the remote authority's SAME original `NativeDeadline`
(or None for an originally local owner). This object is a timing restriction,
not readiness/launch/capacity authority. Do not construct a fresh deadline,
serialize it, extend its duration, or return the peer/owner. Full readiness is
still validated within the same lexical owner before each owned operation.

## Exact consumers and native boundaries

Before the isolated ledger exists, initial prepare uses a single daily scope
outside locks. `_ready` and the first coverage transaction borrow it. Later
operations use the existing two-ledger group, checking the daily member before
locks and beside native operations; isolated-only restore keeps its own scope.
The actual `_coverage_locked` transaction compares the complete original row,
including owner identity, endpoint, paths, manifest and ledger identity. Copied
data does not replace this actual SQL check. DRAINING/SEALED cannot create/set.

After positive SQL close and while retaining the original daily guard, validate
readiness adjacent to Job creation, inert wrapper creation and CPU Set. Carry the
same returned original deadline through setup to the concrete Win32 call:

- Optional `native_deadline=None` on `NativeJob.create`, checked after security
  descriptor setup and immediately before marking/entering CreateJobObjectW.
- Optional `native_deadline=None` on `ScopeLaunch.create_inert`, checked after
  fixture verification/command-buffer setup and before CreateProcessW entry.
- Optional `native_deadline=None` on `set_cpu_rate_unverified`, checked after its
  internal lock and native argument/handle preparation, before Set entry.

Only an exact NativeDeadline is accepted when supplied. Existing callers with
None retain behavior; restore/disable is never restricted by this deadline.
Expiration during setup must preserve original setup owners and known absence,
without falsely marking a native call entered. Constructor/close uncertainty
continues to retain its exact original owner graph. Do not add callbacks or
generic serialized permits. Check existing scope/lease deadlines independently.

`_authorize_launch` validates the same lexical authority before its existing
authorization decision. Its authenticated IPC remains outside all locks. This
slice does not carry a readiness permit into a different process or change the
existing root-launch protocol/deadlines. It must not claim the parent's <=1s
readiness window proves freshness at the later wrapper root Create call.
Serial-provider/native acceptance still has to validate the complete protocol.

## Failure and recovery

Readiness validation is not acquisition: a clean expired/dead-peer rejection
does not create an unresolvable `generation_readiness` acquisition marker.
Unknown original reader/RPC/duplicate/close remains retained and quarantined.
No retry under native/SQL locks and no deadline renewal inside nested scopes.
An explicit later attempt can acquire a new owner only after the former scopes
have positively closed and existing no-replay rules permit that operation.

Restore remains original isolated-only and needs no daily SQL/RPC/readiness or
lease. Exiting a failed daily attempt must positively settle original contexts;
unknown own isolated cleanup still blocks. Existing poisoning is not weakened.

## Required evidence

Use actual scope consumers and an actual DailyReadinessAuthority issued through
synthetic authenticated transport. Test RPC-before-lock ordering, no nested RPC,
exact group selection/restoration, original local pin/replacement refusal, full
generation/file/config/source binding, foreign thread/closed/poisoned owners,
and source-validation/mutex/setup deadline consumption without renewal.
Expire the original deadline during Job setup, wrapper fixture verification and
setter lock wait: the corresponding kernel Create/Set must not be called, while
original setup cleanup remains accounted. Test isolated-only restore after
daily readiness loss and retained uncertainty after failed original close.

Run shared preparation/scope/release, readiness and native primitive regressions
through normal daily admission. Synthetic tests prove source contracts only;
S1-S3, recovery, monitoring overhead and A/B gates remain unverified.

## Primitive implementation checkpoint

The three optional exact NativeDeadline entry points are implemented. Their
checks occur after descriptor setup, wrapper source/buffer verification, or
setter lock/handle preparation, before the corresponding kernel call. Invalid
deadline objects fail before setup. Expired Job creation retains its original
initialization owner and descriptor cleanup outcome; expired wrapper creation
keeps its original not-attempted CreatedProcess. Disable and None callers stay
unchanged. No deadline is reconstructed or renewed.

Four related modules passed 135 tests with zero failures/errors/skips (0.315
seconds runner), including 15 new deadline cases. The planning README records
the equivalent command and private log location. These tests use actual deadline
and ownership implementations with explicit synthetic time/Win32 APIs. Independent
review found no actionable issue. Actual remote scope integration remains work
in progress; this primitive checkpoint does not enable any native gate or daily
activation. Tests use the protected dirty baseline through normal daily admission.
