# P2 legacy mode and retained managed accounting

Date: 2026-09-20. Base: `9e17c07756e0dce6cf956bf0f697642bce33bee0`.
This compatibility repair does not deploy the branch or enable adaptive control.

## Observed gap and repair

Managed admission initially requires resource-v2, but a concurrent caller can
still omit that configuration or revert to legacy mode. Coordinator's legacy
grace projection and Maintainer's legacy local pool projection did not interpret
retained managed demand floors or control/recovery barriers. Reverting the mode
could therefore allow new work while those obligations still existed.

A shared `legacy_lifecycle_blocker()` now checks the authoritative registry and
both allocation tables in the caller's admission transaction. Active lifecycle
rows, tagged/orphan allocations, terminal records whose allocations remain, and
control/recovery barriers require resource-v2 interpretation. Missing, corrupt
or unsupported evidence fails closed. A user exemption does not turn an
unsupported ledger interpretation into valid capacity evidence.

Coordinator applies the check to new legacy admission, existing reservation
reuse, signature handoff and both successful queue retry paths. Local legacy
Maintainer routing and reuse share the check. Explicitly remote candidates retain
their own capacity rules. Positively local v2 reuse must validate real captured
telemetry/configuration and shared capacity; a worker's v2 label alone is not
evidence. Existing work is not killed or suspended, and allocations are retained.

Without retained managed obligations, ordinary legacy admission and cleanup
semantics remain unchanged. Once verified terminal finalization has released the
allocation, a compatible legacy caller can be admitted again.

## Integration and limits

The formal plan requires feature-off and mode changes to preserve lifetime
accounting. This repair makes unsupported fallback explicit rather than treating
the legacy grace path as an equivalent managed accounting implementation.
It adds no new capacity limit and changes no exemption count, duration or policy
entry. The dirty Coordinator freshness, routed-I/O and collector-sample changes
were preserved and excluded from this task's staged patch.

This guard exists in the updated binaries. It cannot fence already-loaded old
writers that do not call it. A coherent writer cutover and native lifetime
provider remain necessary before managed production use or P1 promotion.

## Verification

Environment: Windows build 26340, x64 Python 3.13.3. Clean staged tree
`0c71fbeffbd16003c86c9b8f5b64e14ddb33cadd`, exported with raw Git blob bytes,
passed **356 tests in 18.802 seconds**, zero failures, errors or skips. The
normal live P2 wrapper admitted 1 CPU unit, 0.75 GiB RAM and 0 IO slots;
`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` kept native launch/control tests disabled.

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity tests.test_adaptive_admission_context tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope tests.test_adaptive_legacy_mode
```

The 26 new cases use isolated SQLite data and synthetic capacity/authority.
They cover both allocation tables, grace/TTL, mode changes, orphan/terminal
bindings, exemptions, missing/malformed/stale v2 evidence, same-transaction retry
races, remote eligibility, and unchanged ordinary legacy behavior. Local replay
checks exact-budget success without duplicate demand, over-budget failure and
the original I/O request's disk pressure. The three existing Windows self-process
identity checks do not prove Job launch/control capability.

The first targeted run had 96 passes and two failures: old fixtures explicitly
expected new legacy admission after an incomplete managed binding. For the
release test, both ordinary reservations now predate the injected binding while
the original release assertions remain. The handoff test now asserts denial,
the unchanged original allocation and no second allocation. These are intentional
contract corrections after recording the failures, not baseline suppression.
Independent review also identified and corrected the label-only v2 replay gap.
An intermediate clean candidate passed 354 tests, but further review found that
a matching spec hash alone did not establish that retained resource columns
still represented the whole request. Replay now checks effective CPU, RAM,
physical, Commit, I/O and disk fields before suppressing duplicate demand;
safe legacy null fallbacks must yield the same values. Two added regressions
exercise altered resources and valid null compatibility. The final 356-test
candidate above includes this fix, which also received a clean independent review.

No workload was launched, killed, suspended or capped by the new code. No test
Job, Scheduled Task, exemption, production config or global policy change was
made. Private test manifests and cleanup evidence remain in `.local-adaptive/`.
