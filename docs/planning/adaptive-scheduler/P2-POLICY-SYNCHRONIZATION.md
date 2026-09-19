# P2 native policy synchronization

Date: 2026-09-20. Base: `c286b95e7b75e363b2d7f9be37bd6fe8769089e2`.
Adaptive remains off. This change connects policy synchronization to the existing
launch-claim ledger. It does not supply missing native Job evidence, a launcher,
a guardian or authority to enable CPU control.

## Consumed synchronization and persistent uncertainty

The formal plan requires `ClaimLaunch` and cap-barrier changes to share POLICY.
The new claim path takes the logon-scoped native mutex before entering the native
evidence provider, its per-Job fences and the short claim transaction. The claim
CAS still records `launch_in_flight`, validates the guardian and existing barrier,
and retains the shared allocation. SQLite never waits for the mutex while holding
a transaction. No control/barrier-clear path is introduced by this change.

A mutex can become abandoned when its owning thread exits even if its process
survives. Windows then grants ownership to a waiter; after that waiter releases
it, a subsequent wait may look normal. Therefore an abandonment warning alone
cannot protect persistent state if the recovery-state write fails.

The ledger records a unique policy-operation nonce in a completed short
transaction before waiting for the kernel mutex. The nonce remains through
evidence observation, claim commit or rollback, evidence cleanup and confirmed
mutex release. Only then may an exact matching cleanup remove it. A pending nonce
from another operation causes bounded waiting or denial, never automatic takeover
or a new synchronization domain. An authenticated consumed-claim replay remains
read-only and returns no launch authority.

An initialized marker permanently distinguishes a fresh ledger from one whose
previously established binding has been lost. Missing or malformed initialized
UUID/logon fields are rejected, rather than generating a different mutex name.

An abandoned acquisition records `RECOVERY_HOLD` before returning an error. If
that write fails, the preexisting nonce still prevents a new claim. Unknown wait,
commit, evidence-cleanup or release outcomes retain the guard. A proven ordinary
business rejection can clear only its own nonce after rollback and all cleanup
complete. No failure path clears an existing recovery barrier. Recovery of a
retained uncertain operation requires the future authoritative recovery path;
elapsed time, process exit and a newly created mutex are insufficient.

If final nonce cleanup commits but its acknowledgment or connection close fails,
the nonce may already be cleared. The native release was positively completed
before this transaction; the claim remains consumed, the caller receives an
error, and an authenticated retry cannot receive fresh launch authority. This
post-release acknowledgment case differs from uncertainty while a lock is held.

The extra persistent entry guard is an implementation refinement of the plan's
abandonment contract. It closes the write-failure window across mutex release,
handle destruction and process restart without widening launch authority.

## Native mutex boundary

Names use the fixed Sentinel prefix, OS-verified logon SID and a stored random
instance UUID. The native backend validates the current process identity and
reads back the object's owner and protected DACL, including existing same-name
objects. The single logon ACE requests only synchronization and security
readback (`0x120000`). Native wait time is bounded, and the owning
thread must release the mutex. Busy/owned handles cannot be closed or recursively
entered through another handle in the same thread.

This follows Microsoft's [CreateMutexExW](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexexw),
[WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)
and [GetSecurityInfo](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo)
contracts. Modern Windows excludes low-power time from the native wait timeout;
it is not a wall-clock completion promise through sleep or system stalls.

Synchronization providers and lifecycle evidence providers are distinct trusted
runtime interfaces. Tests inject each explicitly. A valid mutex lease is neither
Job membership nor authenticated IPC peer evidence, and no CLI accepts a caller's
serialized assertion as either form of authority.

## Verification and remaining gates

Environment: Windows build 26340, x64 Python 3.13.3. Clean exported Git tree
`0a350601da87520f53813149f20cf9a899e01285` passed **431 tests in 34.002 seconds**,
zero failures, errors or skips. All tested source/test blobs match the staged
candidate; evidence documentation was finalized afterward. The normal live
Sentinel P2 wrapper admitted 1 CPU unit, 0.75 GiB RAM and 0 IO slots.
`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` kept Job/control spikes disabled.

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity tests.test_adaptive_admission_context tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope tests.test_adaptive_legacy_mode tests.test_adaptive_native_cancel tests.test_adaptive_policy_mutex tests.test_adaptive_policy_scope
```

Of the 431 cases, 421 use portable fixtures and ten exercise Windows native
capabilities. Six native cases are new: five cover the mutex backend and one
consumes the default native provider in an isolated lifecycle ledger. The latter
persists an idempotent recovery hold, verifies its stored OS logon identity and
nonce cleanup, then requires another thread to acquire the exact persisted mutex
binding without abandonment. It leaves the isolated ledger in mode off.

The backend checks actual ACL readback, reopened handles, bounded cross-process
contention and timeout, wrong-ACL collision, wrong logon, and owning-thread exit
while its process remains alive. The two short contender processes exited, and
the tests verified owned handles and threads were cleaned up. No Job, cap,
Scheduled Task, user exemption or workload termination was involved.

The 26 new portable scope tests cover lock/transaction order, durable pre-Wait
entry, exact binding, initialized-binding loss, atomic claim decisions, malformed
provider results, rollback, uncertain cleanup, abandonment, failed hold writes,
new-store retries and read-only duplicate claims. Fifteen portable backend cases
cover invalid inputs, thread ownership, recursion, failed waits/releases and
primary-error preservation. Evidence instrumentation uses SQLite's authorizer
to distinguish policy metadata from real lifecycle/capacity mutations; adding a
policy column to an unrelated write cannot exempt it from evidence assertions.

The first standalone mutex run passed 20 tests in 0.946s; the focused integration
run passed 126 in 10.957s. The first clean integration run executed 423 tests and
reported eight subtest failures in two existing corruption-matrix methods. Those
methods reused one DB across independent damage scenarios: the first corruption
correctly left a nonce, so subsequent cases hit the new guard. The ten scenarios
are now separate test methods/DBs, retaining every original exact error/state
assertion and additionally requiring the uncertainty nonce to remain. This
accounts for the eight-test count increase; no production guard was relaxed.

Independent source and test reviews are clean after correcting lost-binding
reinitialization, timeout-cleanup error preservation and the test isolation.
Native mutex tests use isolated random names, short test processes and test
threads. Positive claim fixtures still use synthetic Job evidence; these results
cannot pass the native launch, control, recovery, overhead or A/B gates. Universal
participation by legacy writers, authenticated IPC, authoritative unresolved-nonce
recovery, the independent launch host and continuous-admission prerequisites
remain unfinished. Full native lifecycle and P3-P6 are not complete.

Daily source/config and global policy entry points were not changed by this
slice. The production config SHA256 remains
`75BDD2E0EA382804A95E40C9BCA82D607A9FF96FA44A721DF0908D9049D533F9`.
Private candidate, runtime hash and exact reservation-release records remain in
`.local-adaptive/`; runtime databases/configuration are excluded from commits.
