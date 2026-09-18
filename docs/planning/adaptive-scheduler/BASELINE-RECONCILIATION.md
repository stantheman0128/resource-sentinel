# P0 baseline reconciliation

Date: 2026-09-19 (Asia/Taipei). Status: P0 passed at 04:43:11; inventory/source
reconciliation and unchanged baseline suites completed. P1 is not yet verified.

## Evidence and isolation

- Live repository HEAD: `0b2f37819a2d4f68299fbec3fe619a4d05ba4749`, branch `master`.
- Formal plan fetched from `codex/adaptive-scheduler-planning` at
  `68b14eb0a2db19e709934e9beb08c30322326535`; 1,200 lines, Git blob
  `262256427b782ca1eee05456ff9e23bfe3e1cc5e`. The plan is already in this branch's ancestry.
- Implementation branch: `codex/adaptive-scheduler-implementation`, separate worktree.
  Existing planning worktree remains at `b1b384e8d5121b3699bf84411f5c36858b66d607`.
- At handoff: 16 modified tracked files, no staged changes, plus pre-existing
  untracked implementation/docs/tests. Seven pre-existing `tests/tmp*` directories
  could not be read by the sandbox; none were removed or altered.
- A local-only manifest, full pre-existing binary diffs, Git inventory and worktree
  inventory are retained under `.local-adaptive/p0/` in the implementation worktree.
  They are not staged or published. No config, DB, environment dump, command output,
  or private conversation is included in this report.
- 39 allowlisted live source/test/doc files were copied into the isolated tree,
  with matching before/after SHA-256 and unchanged live source. These are a local
  test overlay, not authorization to commit pre-existing changes. No snapshot was
  copied over executable source.
- All 15 reference snapshots match their recorded SHA-256. Seven live files differ
  from those snapshots: `collect.ps1`, `invoke-sentinel.ps1`, `sentinelctl.py`,
  `collector-health.ps1`, `coordinator.py`, `exemptions.py`, `test_exemptions.py`.
  Differences include dashboard health/observability, bounded export, sample
  timestamps and persisted lease display attribution added after planning capture.

## Fixed policy and environment

Allowlisted live configuration: `admission_policy=resource-v2`, machine RAM admission
budget 58 GiB, physical reserve 4 GiB, Commit reserve 4 GiB. The live exemption module
enforces a maximum of three unexpired/unrevoked leases with an atomic transaction.
No configuration was changed, and no exemption was granted for this work.

Observed environment: Windows 11 build 26340, x64 Python 3.13.3, 12 logical
processors, one processor group. Windows PowerShell 5.1 and bundled `pwsh` are
installed. An initial read-only probe of the sandboxed Python process reports
existing Job membership; its denominator/ownership is not known. This is not
capability approval. P1 must reject foreign Jobs and report the actual tested host.

## Source reconciliation findings

References below are live source symbols; line numbers are intentionally not used
as permanent contracts because the local overlay is uncommitted.

| Area | Verified live fact | Required follow-up |
|---|---|---|
| Missing dirty Maintainer | `Maintainer.route_and_reserve` consumes local v2 `admission_snapshot` and `admission_config`, validates freshness and invokes `resource_blockers`. `test_local_worker_uses_same_commit_guard` tests Commit 74/limit 77 and expects `commit_capacity`. | Source gap in plan §0 resolved; unchanged baseline test passed. |
| Shared ledger | Coordinator and Maintainer use the same `sentinel.db` and `BEGIN IMMEDIATE`, but compute capacity differently. | P2 common projection, preserving remote pool behavior. |
| Local aliases | Coordinator filters routed demand by one configured worker ID; Maintainer filters routed rows by the selected capacity pool. | Same-host aliases can omit each other's routed demand. Canonical host/pool binding and race tests required. |
| Grace/accounting | Coordinator stops counting pending CPU/RAM after grace; Maintainer counts active rows. | Active monotone demand floors, validated subtraction, common units/projection. |
| Identity/cleanup | Direct cleanup looks up OS identity inside the transaction, uses float tolerance, treats lookup errors as dead, and releases on TTL. Routed cleanup archives expired reservations. | Exact native identity, tri-state observations outside transactions, managed TTL-to-hold. |
| Wrapper lifecycle | App ancestor usually owns reservation. `cmd.exe` root return reaches finally/release; no running heartbeat or child-empty verification. | Exact execution allocation and guardian ownership before managed use. |
| Hook handoff | Exact wrapper bypass exists. Legacy handoff uses owner/signature/oldest row; PostToolUse reaches legacy release. | Retain bypass; managed exact claim tokens and release protection. |
| Stop hook | Already exact-cancels a queued request; does not release active reservations. | Preserve and cover; no invented owner-release fix. |
| Collector ancestry | Collector timeout uses `taskkill /T /F`; collector can synchronously tick orchestrator, which launches local runner and command. Runner uses NEW_PROCESS_GROUP/NO_WINDOW, not proof of independence from ancestry. | S2 fixture test; no new guardian/helper in this subtree. No claim that a user's real job was killed. |
| Legacy writers | CPU demotion, I/O mutation, exemption restoration and trim are separate collector paths. Wrapper exemption handling can also restore its own priority. | P3 must cover every path; a single feature flag around one stage is insufficient. |

The latest live README contains two mismatches to the actual implementation:
selected local work is described as automatically going through the wrapper, but
the built-in adapter executes the submitted command directly; and total-color
local routing is described although the v2 sync path publishes AVAILABLE and
defers to resource guards. Explicitly putting a wrapper in a routed command does
not yet adopt the routed allocation and can double-reserve. README claims are not
used as evidence that these contracts are already satisfied.

Canonical integration is present: `docs/agent-bootstrap.md` and
`docs/agent-policy.md`. The primary Codex entry has one start marker, one end marker,
one policy link, and normalized body equality to bootstrap. Other agent entries
were not re-audited. No adaptive rules or parameters were appended globally.

## Baseline validation

Tests run against the isolated **live overlay**, not the older committed root or
the text snapshots. The harness records independent exit codes and leaves test
expectations unchanged. Admission uses the live normal P2 wrapper with one CPU
unit, 0.5 GiB RAM and zero heavy-I/O slots. A capacity wait is not a test pass/fail.

Before execution, 68 allowlisted source/test/doc files were frozen in a separate
local `baseline-root`; all 39 live-overlay hashes match the initial manifest.
This avoids testing the independently developed disk fix as if it were baseline.
Tests ran 04:41:52 through 04:43:11 after normal admission, without exemptions.

| Command | Result |
|---|---|
| `py -m unittest tests.test_coordinator tests.test_pressure tests.test_exemptions tests.test_maintainer tests.test_hooks` | PASS: 72 tests, 76.232 seconds, 0 failures/errors/skips; exit 0 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_exemption_policy.ps1` | PASS: 9 assertions and 3 script parse checks; exit 0 |
| `powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_collector_recovery.ps1` | PASS: health, stale/partial/future/malformed data, bounded probe timeout, mocked scheduler recovery ordering and verification; exit 0 |

PowerShell's redirected native stderr wraps unittest progress as NativeCommandError
text; the Python process exit was 0 and unittest reported OK. This is not a test
failure. No original baseline failure or environment skip was observed in these
selected suites. Collector recovery's scheduler calls are deliberately mocked;
this does not establish the new P1 Windows recovery capability.

No Windows Job control/canary, full-suite success, A/B performance result or
production integration is claimed. No new Job restriction exists to withdraw.

## Commit boundary and next gate

Pre-existing runtime changes remain unstaged. New P0 documents and future test-only
capability spikes can be committed independently. Before P2 integration is shipped,
any dependency on unpublished live modules must be made explicit; do not silently
include the existing dirty baseline in an implementation commit or claim the clean
branch reproduces the local-overlay test results.

Next gate: isolated S1/S2/S3 as P1. Official-API boundary clarifications are recorded
in [P1-API-PREFLIGHT.md](P1-API-PREFLIGHT.md), without claiming capability success.
Production adaptive remains off. Disk-alert attribution
improvements requested separately are isolated in their own diff and tests; they
do not change the adaptive plan or enable CPU control.

Handoff update: P1 launch-host probing rejected both observed hosts because of
unknown parent Job membership; see CAPABILITY-RESULTS.md for the actual failure
and verified test-task removal. P2–P6 remain held at this gate. The separate disk
patch passed its Windows fixtures and was committed without collector activation.
The user's later exemption-visibility request was verified and applied locally as
a display-only fix. Of the 39 baseline files, only attribution.py, dashboard.py
and the dashboard Node test changed in protected main for that request; HTML and
one new fixture test were also deliberately updated. Other captured files remain
byte-identical. Runtime policy/configuration, Scheduled Tasks, leases and adaptive
control were unchanged. See the new exemption-visibility work note for the exact
commit/dependency and live-publication boundary.
