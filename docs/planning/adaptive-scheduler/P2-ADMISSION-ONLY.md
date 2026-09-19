# P2 admission-only implementation evidence

Status: P2-A source foundation implemented, independently reviewed and tested;
native enrollment disabled. This is not the full P2 native-lifecycle exit gate.

## Scope and gate interpretation

The formal plan's sections 2.1, 10/P1 and 13.4 permit deliverable A when native
capability gates fail. This change implements isolated admission/lifecycle and
shared-accounting foundations. It does not claim P1 passed, a production policy
mutex exists, trusted native evidence is implemented, or that P2's complete
native handoff is available. P3–P6 promotion remains blocked.

No production config, grant, Scheduled Task, global instruction entry or active
controller is changed. The live 58 GiB / 4 GiB physical / 4 GiB Commit policy and
three-lease enforcement remain authoritative. No automatic exemptions, kills,
Suspend/Resume loop, memory caps or additional CPU writers are introduced.

## Contracts being verified

- Additive versioned SQLite metadata binds each execution to one existing direct
  or routed allocation, or a positively verified parent allocation. Exact native
  FILETIME values use decimal strings on the wire. Claim tokens are stored only
  as hashes. Commands/cwd are represented by keyed digests, not raw persistence.
- Root exit, expiry, legacy release, feature-off and uncertain identity retain
  bound capacity. Trusted positive empty evidence and a sealed launch are
  required for finalization. Production verification defaults to unavailable;
  synthetic test evidence cannot be supplied through the CLI.
- Both admission paths project all same-host direct/routed demand in the same
  transaction. Local aliases and per-execution labels do not create independent
  host capacity. Unknown locality blocks admission; explicit remote allocations
  remain outside local accounting. Active demand is never aged out by grace.
- Physical usage and private Commit stay separate. Subtraction requires exact,
  complete and comparable attribution. Missing, stale, overlapping or invalid
  evidence subtracts zero. Demand floors cannot decrease after a cap.
- Direct and routed requests accept separate Commit estimates. Direct requests
  preserve the value through queue, retry, handoff and reservation; omitted
  estimates preserve legacy hashes and RAM-based estimates. The queue column
  upgrade is serialized with the additive migration, including concurrent old
  database constructors.
- OS identity/ancestry reads occur before write transactions and observations
  are tied to unchanged row identities. Unknown schema is rejected before writes.

## Publication boundary

The protected main tree was captured again before work resumed. New modules and
tests are task-owned. Existing Coordinator/Maintainer/CLI files use explicit
HEAD-based candidates, excluding unrelated pre-existing dirty hunks. Minimal
prerequisites needed for v2 snapshot transport and finite resource validation
are reviewed and identified, not attributed as newly discovered baseline fixes.

The earlier local Maintainer Commit guard already existed. This work replaces
its separate projection with common accounting; it does not claim to have
introduced Commit protection. Unpublished dashboard/attribution/pressure modules
are not dependencies of the clean candidates.

The original committed baseline and local live baseline still differ outside
this task. In particular, the pre-existing live exemption-policy changes are not
swept into these commits. Production readiness requires reconciliation of those
remaining baseline differences; the standalone display reader reports unknown
enforcement limit on old code without an authoritative limit constant.

The local dashboard's v2 preview was also aligned with common accounting. Its
pre-existing modules cannot be swept into this commit. Only the task-owned
compatibility delta is published in `integration-patches/live-dashboard-p2.patch`,
with before/after source hashes and explicit protected-baseline prerequisites.
The standalone exemption display is independently committed and tested from a
clean checkout. Neither form is automatic deployment.

## Validation log

First combined L1 run: 98 tests, one failure and seven errors. The JSON nesting
test exposed a missing explicit depth bound. Seven new Coordinator fixtures
left SQLite connections open, causing Windows temporary-directory cleanup
errors; behavior assertions reached completion. These are new implementation
and fixture defects, not reclassified baseline failures. Evidence is retained;
both defects were corrected. Independent review additionally found and fixed
schema-before-WAL ordering, exemption integrity bypass, floor-write version
validation, atomic ten-Job preparation, stale claim proof revisions, terminal
replay, typed evidence, complete protocol fields and the sample-bounded guardian
deadline. The final Commit-column constructor race also has a real two-connection
regression; its migration now uses `BEGIN IMMEDIATE`.

Final clean candidate archive: **136 P2 L1 tests passed** (3.463 seconds), followed
by **42 committed-baseline Coordinator/Maintainer/exemption/hook tests passed**
(64.778 seconds), no skips. Earlier clean checkpoints passed 127+42, then 153
including independent exemption display tests, and 135+42 before the final
migration-race correction. These overlap; do not add them into a unique count.

A separate 265-test live-baseline run found one real dashboard parity failure:
its preview still used the old pressure/grace calculation. The original parity
assertion was retained; the preview now reads the shared projection/blockers in
one read-only transaction, with OS inputs captured beforehand. The routed
fixture was upgraded to the real schema/locality contract and five regression
cases were added. The final protected-live-baseline rerun passed **279 tests**,
84.986 seconds, zero skips/failures/errors. The full existing Node dashboard
rendering suite also passed, including stale/missing data, escaping, pause/resume
and persistent panels. No browser visual acceptance is claimed.

The three-file compatibility patch reconstructed exactly the manifest's
LF-normalized after hashes and current source in a private fixture. The first
patch check incorrectly compared CRLF output from Git against LF hashes; that
harness-only comparison was corrected without changing the patch or old evidence.

Execution environment: Windows 11 build 26340, 64-bit Python 3.13.3. All test
groups used normal P2 admission (one CPU unit, 0.5–0.75 GiB RAM, at most one IO
slot), sequentially; no exemption or policy adjustment. The protected main
tree's 41 captured source/test/doc hashes and HEAD remained unchanged.

Reproduction commands for the clean implementation source:

```powershell
py -m unittest tests.test_adaptive_contracts tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_coordinator tests.test_adaptive_maintainer tests.test_adaptive_query
py -m unittest tests.test_coordinator tests.test_maintainer tests.test_exemptions tests.test_hooks
py -m unittest tests.test_lease_display
node tests/test_exemption_display.cjs
py -m unittest discover -s tests/windows -p 'test_adaptive_desktop*.py'
```

Each non-light command must be run through the existing normal admission wrapper.
The last command runs pure probe fixtures, not native dispatch/control. Native
host/recovery gates are explicitly separate. The 279-test command below additionally
requires the protected live baseline and the verified compatibility patch; it is
not a claim that these uncommitted prerequisite modules exist in clean HEAD:

```powershell
py -m unittest tests.test_coordinator tests.test_pressure tests.test_exemptions tests.test_maintainer tests.test_hooks tests.test_agent_policy tests.test_claude_session_attribution tests.test_dashboard_observability tests.test_adaptive_contracts tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_coordinator tests.test_adaptive_maintainer tests.test_adaptive_query tests.test_lease_display
node tests/test_change_dashboard.cjs
```

The native desktop preflight has separate capability evidence in
`CAPABILITY-RESULTS.md`. It is not included in L1 admission pass claims.

## Remaining integration limits

- Native launcher, guardian evidence, cross-process policy mutex and recovery
  supervisor are unavailable. Mutation paths require trusted verification and
  fail closed by default. No user-provided `empty=true` assertion can release
  an execution.
- Old local/remote records lacking a trustworthy locality assertion now block
  v2 local admission conservatively. Do not infer locality from provider names
  or silently rewrite the live registry to force admission.
- Old tokenless waiters and hooks retain legacy admission-only behavior. They
  cannot claim an execution-bound allocation through signature guessing.
- Active control, monitoring overhead and A/B gates are not established by
  these tests. Default mode remains off.
