# P2 persistent capacity-writer compatibility fence

Date: 2026-09-20. Implementation base: `2947add967d5d88ede0efd3e26e9f78d4a3bde96`.
This is an admission-only accounting repair under the independent P2 deliverable.
It does not pass the Windows launch/control gates or deploy the daily runtime.

## Problem and contract

The updated Coordinator and Maintainer preserve managed allocations and lifetime
demand floors. A process that imported an earlier binary does not call those
checks. Its ordinary INSERT can omit retained demand; its cleanup/release DELETE
can erase a managed allocation. Feature-off and TTL expiry do not remove these
obligations. Updating files alone does not replace already-loaded code.

Persistent SQLite triggers now reject incompatible capacity mutations while
managed obligations or control/recovery barriers exist. The two existing ledgers
and worker registry receive additive `writer_protocol` and `writer_revision`
columns. Protected INSERT requires protocol 1/revision 0; protected UPDATE
requires protocol 1 and the exact next integer revision. A historical protocol
marker alone cannot authorize an old UPDATE that leaves new columns unchanged.
Markers are cooperative implementation metadata, not caller authentication or
proof that the capacity projection ran. No optional connection UDF is required.

Obligations include nonterminal or malformed lifecycle records, tagged/orphan
allocations, registry back-references whose capacity tags were stripped, retained
terminal allocations, and unknown/malformed runtime/barrier state. A valid
opposite-kind reservation ID remains in its separate direct/routed namespace.
An invalid allocation kind cannot erase a matching unresolved back-reference.

Capacity DELETE requires an exact matching terminal, sealed, non-in-flight
lifecycle binding. Conflicting references retain the allocation. INSERT OR
REPLACE and UPDATE OR REPLACE are checked at the incoming operation, including
ID, request/task key, execution-ID and explicit rowid collisions; the fence does not depend on
SQLite `recursive_triggers`. Referenced worker replacement/deletion is also held.

Current Coordinator, Maintainer and lifecycle mutations explicitly participate.
Worker refresh uses UPDATE-if-present/INSERT-if-absent under its existing writer
lock, preserving the active allocation locality check. Old worker registry writes
are conservatively fenced across both local and remote workers during obligations;
SQL does not attempt a second interpretation of Python's locality rules.

## Transaction and schema integration

Both capacity schemas, their worker registry and release archives must exist and
be guarded before managed admission. Otherwise a normal old constructor could
create a previously absent peer ledger without installing its triggers. Migration
therefore prepares the complete existing capacity schema under one writer lock;
it creates no third ledger. Known additive legacy columns are preserved, and an
unrecognized incomplete existing schema is rejected rather than filled with
invented row data. Migration never repairs retained allocation locality values.

Constructors keep initial schema creation, additive migration and guard
installation in one transaction. Caller-owned migration does not commit or roll
back caller work. Maintainer skips legacy locality backfills when obligations are
present. Trigger definitions are regenerated from the migrated schema in that
same transaction, avoiding an exposed interval without guards.

Lifecycle finalization now performs its terminal compare-and-set before archive
and allocation deletion, under the same retained proof and SQLite transaction.
Any archive or deletion failure rolls back all preceding lifecycle changes and
keeps the allocation. Nested finalization rolls back descendant changes too.
Successful retries archive once. The prelaunch custody digest excludes the
incidental writer revision but still binds writer protocol and semantic fields.

## Boundaries and rollback

Healthy legacy operation without managed obligations remains supported. The fence
is not a security boundary against arbitrary same-user SQL or schema tampering.
It also cannot intercept a SELECT-only historical retry that returns an existing
reservation as allowed. The frozen legacy test deliberately preserves that
negative result. Coherent caller/launcher cutover remains required before managed
production admission; DML coverage alone is not a trusted continuous provider.

The 58 GiB machine budget, physical and Commit reserves, three-exemption cap,
lease deadlines and policy entrypoints are unchanged. No new native control,
automatic exemption operation, CPU/I/O/trim writer handoff or capacity release on
feature-off is introduced. The native spike prerequisite remains closed.

Rollback retains additive schema and triggers while obligations survive. Do not
restore an older database or remove guards to make old callers run. With no
managed obligations, old cooperative admission/cleanup remains available; the
full native migration still requires its separate release/recovery evidence.

## Validation evidence

Environment: Windows build 26340, x64 Python 3.13.3. Final exact Git tree
`08210b18885db6f661e9fe793f94b2a2bcb57f98` passed **593 tests**, zero failures,
errors or skips, in 38.480 seconds including test loading. All staged source/test
blobs matched that clean export; only evidence documentation was finalized after
the run. This is 577 portable cases and the same 16 Windows native
identity/synchronization/query cases already exercised by the IPC slice.

The 65 added cases comprise 39 SQL fence cases, 18 real frozen historical-writer
cases and eight lifecycle release rollback cases. Additional subcases include six
explicit rowid replacement collisions. The historical fixture preserves 42
definitions from public commit `0b2f37819a2d4f68299fbec3fe619a4d05ba4749`;
their individual hashes and original blob IDs are checked. It imports no current
admission helpers. Only filesystem mirror output and exemption lookup are
explicit test seams. These tests make no new native launch/control claim.

The first clean candidate `5aa72b52660280461d7a63a28537906ea9b98bad` ran 536
tests: 7 failures, 66 errors, zero skips, 28.809 seconds including test loading.
Raw logs remain private. Many errors occurred before intended lifecycle assertions
because synthetic allocation or corruption setup did not acknowledge the new
cooperative writer protocol. Constructor concurrency instrumentation was moved
before the real writer lock and now also asserts that migration reads occur
inside that lock. These failures were recorded before fixture
changes. Original lower-layer rejection and retention assertions are retained;
deliberate storage corruption is explicit and confined to isolated databases.

Independent review found the absent-peer-ledger bypass described above. The
corrected candidate includes passing regressions using historical constructors
in both orders. Two intermediate 593-case candidates each had one remaining
fixture setup error, zero assertion failures/skips: trees
`ca4c93e1d62bb7b34d640d5f8f11b20a5d53c02e` (38.724 seconds) and
`b3ba9fcd22778fe67d1970225b422f1be9b438d5` (37.740 seconds). Their synthetic
signature-handoff UPDATE lacked the protocol acknowledgement. The final narrow
fixture correction preserves denial, exact original allocation and no-new-work
assertions; no production guard was relaxed.

The full module command was executed by the private evidence harness against
raw Git blob exports, with `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`:

```powershell
py -X utf8 -m unittest `
  tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle `
  tests.test_adaptive_accounting tests.test_adaptive_maintainer `
  tests.test_adaptive_coordinator tests.test_adaptive_contracts `
  tests.test_adaptive_query tests.test_maintainer tests.test_coordinator `
  tests.test_orchestrator tests.test_adaptive_allocation_transitions `
  tests.test_adaptive_identity tests.test_adaptive_admission_context `
  tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope `
  tests.test_adaptive_legacy_mode tests.test_adaptive_native_cancel `
  tests.test_adaptive_policy_mutex tests.test_adaptive_policy_scope `
  tests.test_adaptive_ipc_admission tests.test_adaptive_ipc `
  tests.test_adaptive_pipe_windows tests.test_adaptive_native_ipc `
  tests.test_adaptive_writer_release tests.test_adaptive_writer_fence `
  tests.test_adaptive_legacy_writer_fence
```

Every run used the normal live P2 wrapper at 1 CPU unit, 0.75 GiB RAM and zero I/O
slots. One run waited for Commit capacity and resumed through normal admission
with unchanged estimates. All four exact test reservations were verified absent.
The 35 previously inventoried daily source paths and production config hash
remained unchanged. The installed 104 skill still matched its validated hashes;
the global resident MCP entry remained disabled.

No test Job, CPU cap, Scheduled Task, exemption, resident daemon, production
deployment or global policy change was introduced. There are no new Job limits
to withdraw. Test duration is not P4 monitoring-overhead or P6 workload A/B
evidence. Independent source and fixture reviews completed without remaining
actionable findings in this slice.

## Remaining full-lifecycle gate

P0 remains complete; this slice extends P2 admission-only accounting. The prior
read-only P3 IPC slice remains available. P1 controlled launch/recovery and full
P3-P6 promotion remain blocked by the unverified Windows launch environment,
missing trusted continuous daily lifetime-floor provider and required coherent
entrypoint/writer cutover. The current native spike guard is still unconditional.
No daily deployment or production adaptive activation is authorized by this
source task. Guardian/launcher ownership, exemption and legacy control-writer
handoff, fast sampling/shadow overhead, controlled recovery canary and real-command
A/B evidence are still required.
