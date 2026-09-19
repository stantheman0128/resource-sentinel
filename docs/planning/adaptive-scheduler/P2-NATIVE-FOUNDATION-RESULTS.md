# P2 native identity and retained-allocation checks

Date: 2026-09-20. Base: `9bfc7d3bf8e6efc28b1d66ed41260f0c59bc3232`.
Status: implemented and tested, with adaptive off. These changes do not complete
native lifecycle, satisfy P1 S1-S3, or promote P3-P6.

## Implemented contracts

`sentinel/adaptive/identity.py` provides a retained, limited-right process handle:
`VerifiedProcess.current()` bootstraps the current wrapper; `open(expected)`
requires matching PID, exact integer creation FILETIME and target token logon
SID. Subsequent liveness and membership observations use that same handle.
Only a signaled, verified handle is death evidence. Access/query failure,
identity mismatch and a closed handle produce UNKNOWN rather than death.
Membership queries check liveness before and after querying; out-of-range Job
handles are rejected before ctypes can truncate them. The context owns and
closes its process handle, never the supplied Job handle.

This API is observation infrastructure, not IPC peer authentication, allocation
ownership, a launch fence or a continuous-admission provider. It does not launch
processes, enumerate the machine, open a database or call a mutation API.

`validate_active_allocation()` in the existing accounting module resolves the
same direct/routed allocation used by admission and validates its binding,
immutable resource request, monotone floor, spec, routed task and local host.
Lifecycle registration, active registration retries, preparation and the first
launch claim call it in their existing short write transaction. Native evidence
still runs outside that transaction. Corruption between verification and claim
cannot consume the launch token or grant launch authority. TTL is deliberately
not a release condition. Finished retries remain possible after verified release.

Routed registration now checks the actual task ID before binding. Nested
registration verifies each ancestor's logon/state and the ultimate allocation;
failure rolls back the new subspan and never creates a second reservation.

## Verification

Environment: Windows build 26340, Python 3.13.3, 64-bit. Production native
control spikes remained disabled (`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`).

The focused run passed **67 tests in 4.386 seconds**, zero failures/errors/skips,
through normal P2 admission (1 CPU unit, 0.5 GiB RAM, 1 IO slot):

```text
py -X utf8 -m unittest tests.test_adaptive_allocation_transitions tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch
```

An initial sandbox attempt could not open its temporary SQLite directories and
also failed temporary-directory cleanup. It did not exercise the test bodies.
The normal-admission run above used the required filesystem access; no assertion
was changed to conceal that environment failure.

A separate clean export contained the committed base plus exactly the five
source/test files in this change, excluding all protected dirty overlay files.
Its **266 tests passed in 10.401 seconds**, zero failures/errors/skips, through
normal P2 admission (1 CPU unit, 0.75 GiB RAM, 0 IO slots):

```text
py -X utf8 -m unittest tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_maintainer tests.test_adaptive_coordinator tests.test_adaptive_contracts tests.test_adaptive_query tests.test_maintainer tests.test_coordinator tests.test_orchestrator tests.test_adaptive_allocation_transitions tests.test_adaptive_identity
```

Of these, **265 are portable tests and one is an actual Windows read-only
current-process identity smoke**. The latter verifies exact identity, logon SID,
reopening, same-handle liveness/membership and cleanup. It does not prove Job
launch, CPU effect, recovery or observer/A/B gates. Native control suites were
not included and are not counted as passed or skipped.

The nine new ledger tests cover adoption task mismatch, missing/rebound/corrupt
capacity during claim, altered routed locality, a regressed floor, retry after
capacity loss, invalid nested ancestry, and terminal replay. Independent review
reported no actionable ledger regression. Identity review found handle integer
overflow and an exit/membership race; both were fixed and regression-tested
before the clean export, then re-reviewed. Tested file hashes still matched the
working files after execution. Private manifests remain in `.local-adaptive/`.

Both exact normal test reservations were confirmed absent afterward. Sentinel's
production config SHA256 remained
`75BDD2E0EA382804A95E40C9BCA82D607A9FF96FA44A721DF0908D9049D533F9`.
No exemption, Scheduled Task, production entry point, CPU limit or test Job was
created/changed; therefore this continuation introduced no OS cap to withdraw.

## Remaining implementation and promotion boundaries

The default lifecycle verifier still rejects native registration. In particular,
proving a proposed wrapper is alive does not authorize it to adopt a matching
legacy reservation. Legacy float owner timestamps and unkeyed spec hashes cannot
be promoted to exact native ownership. Trusted task/session/principal resolution,
atomic admission-to-registration, one-use adoption, peer authentication and
native launch/restore reconciliation remain required.

The next implementation seam is a managed admission transaction using the same
existing ledger: a trusted, retained caller context must designate the exact
wrapper; admission and RESERVED binding must commit together. Keep a managed
HMAC of the in-memory launch payload separate from legacy spec hashes, and bind
any adoption credential to that exact execution/allocation/caller. Do not call
legacy `admit()` and then bind through a second connection, accept owner JSON as
authentication, or mint a replacement credential after a lost acknowledgement.
No managed CLI is enabled by this change.

P1 still has two independent blockers: unknown external Job membership and lack
of trusted continuous host accounting throughout the long native suite. A
read-only follow-up found correct IsProcessInJob ABI and corroborated the old
probe's held-handle identity checks. The current Python interpreter has an
asInvoker/Windows-supported manifest; its isolated startup path and checked PCA
events supplied no Job-assigner attribution. These narrow hypotheses, not proof
of a supported host. Another unchanged membership-only launch is not warranted.
The next attribution diagnostic would need bounded Job object/holder evidence
from a currently held exact process, without closing handles or changing Jobs.

No deviation from the frozen safety invariants is introduced. Full native
lifecycle and P3-P6 remain unfinished; portable tests and this read-only smoke
must not be described as completing them. Daily runtime deployment remains
outside the authorization for this implementation task.

API references: [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[GetTokenInformation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation),
[TokenLogonSid](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class),
[IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob).
