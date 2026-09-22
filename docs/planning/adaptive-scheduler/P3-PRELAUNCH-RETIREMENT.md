# C2: positive prelaunch retirement evidence

2026-09-22. Contract for README ruling ②, written before implementation.
This clarifies plan §§4.2–4.5 and retained-supervisor retirement. It changes no
capacity limit, exemption, control eligibility or native acceptance gate.

## Authority and the irreversible boundary

`CANCELLED_BEFORE_START` and `START_FAILED` may retire a named scope only with
positive proof from the guardian that retained its original Job creation handle.
An empty Job, missing root/PID, expired lease, closed handle, timeout, caller
failure string or missing manifest is not that proof.

The new wrapper launch protocol explicitly binds version 1 of a shared launch
fence at ClaimLaunch. Old/unknown protocol claims cannot use post-claim failure
retirement. The wrapper acquires the same per-execution/nonce native mutex as
the guardian, re-reads exact immutable identity, claim revision, LAUNCHING state,
unsealed launch and current allocation, and holds the mutex across the one
CreateProcess call. It never calls IPC or acquires POLICY while holding this
mutex. It releases it before BindRoot. Guardian order stays POLICY then Job.
An abandoned mutex or uncertain release is HOLD, not permission to retry Create.

For a retained Job, the guardian queries lifetime `TotalProcesses`, current
`ActiveProcesses`, the PID list, CPU state and Job limits while holding POLICY
and that same Job mutex. All process counts must be zero, the PID list empty,
CPU disabled, and prohibited Job limits absent. Its exact durable manifest must
be rootless, have no pending intent/applied cap, and match the original guardian,
execution, reservation, nonce and floor. TotalProcesses includes processes that
have exited; it is not interchangeable with ActiveProcesses. The original
handle must have been retained continuously; reopening a name cannot establish
this proof. [Microsoft accounting contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information).

Before the first native Job creation attempt, the original guardian may instead
irrevocably seal its in-memory creation capability, settle its initial manifest,
and prove `job_creation_never_attempted`. No native zero counts are invented.
An attempted/unknown Job creation cannot use this alternative. A RESERVED row
with no named scope stays on ManagedAdmission's existing unexported-claim path.

## Cancellation and failed launch are different

An authenticated exact cancel before claim finishes as CANCELLED_BEFORE_START.
After claim it only records `cancel_pending_reconciliation`, even if currently
empty. It does not stop, signal or throttle anything. A separate authenticated
StartFailed request can irreversibly abandon a failed attempt only when the
guardian proves never-started under the launch fence. The wrapper seals future
launch locally before requesting it. Guardian's terminal CAS seals the durable
claim before releasing the fence, so a delayed wrapper is rejected on re-read.
Already associated processes, including very short commands, forbid StartFailed.
Lost Create/Bind outcomes keep their original custody and never cause a second
launch. Requests carry identifiers only, not a boolean asserting native failure.

The proof does not require fresh admission or renewed capacity: retirement is a
release/reconciliation path. It still validates the exact active allocation,
immutable binding, guardian identity and existing POLICY fence. No allocation
may be substituted, enlarged, or taken from another wrapper. Native observations
happen before SQLite writes; locks stay held through CAS and archive commit.

## Durable retirement, replay and cleanup

In the same transaction as terminal CAS/archive, named prelaunch retirement
records a bounded proof receipt binding execution, final state/revision, Job
nonce, immutable manifest hash and guardian identity, plus the evidence kind
(never-created or never-associated). It records zero lifetime count only for an
actual native observation. Only the in-process evidence provider supplies it.
No CLI accepts this receipt or lets a caller choose its facts.

Supervisor inventory considers these terminal rows for retirement only after
checking the receipt, exact settled manifest, exactly one matching terminal
archive and absence of active allocation. A state string without that receipt
stays an obligation. This extends retained-terminal validation; it never changes
the FINISHED/barrier-clear contract to accept an unstarted row.

Authenticated RPC retries keep the same request ID, payload and original
revision. An exact lost-ACK replay revalidates terminal evidence; it cannot
release twice, mint a new claim or relaunch. Ambiguous SQL or journal failure
retains the owner and its fences for reconciliation. Cleanup closes only owned
handles after terminal proof. A cleanup error keeps exact owners reachable and
retryable according to their existing native cleanup contracts. Guardian ticks
retry committed-terminal cleanup so an RPC receipt loss cannot strand shutdown.

## Verification required

Use isolated SQLite/journals and synthetic native backends for portable evidence:
preclaim cancel, postclaim pending cancel, known zero-history failed launch,
exited-before-bind refusal, active/unknown counts, non-disabled/limited Job,
wrong caller/nonce/revision/manifest, lost terminal ACK, duplicate archive,
missing/tampered proof, partial cleanup and delayed-launch race. Prove the
wrapper holds the shared fence around native creation and releases before IPC.
No new test may stop, cap or crash a user's workload. Portable success is not
native S1–S3, P3, P5 or P6 acceptance. Adaptive remains off.

## Implementation checkpoint

The production wrapper now fences native creation and the authenticated launch
transport includes CancelBeforeStart/StartFailed plus an explicit ClaimLaunch
protocol version. The original guardian emits the proof; SQLite archives it in
the same transaction as release; the supervisor requires it before retirement.
The guardian host retries terminal handle cleanup each tick. An exact running
cancel replay can observe DRAINING or FINISHED without inventing prelaunch
failure. The same original guardian can settle an initial manifest after a cut
between scope registration and manifest construction, before any Create attempt.

Targeted verification: 40 tests across `test_adaptive_guardian_retirement`,
`test_adaptive_prelaunch_retirement_store` and `test_adaptive_p3_flow`, with
0 failures/errors/skips. These run
with isolated real SQLite/journals, explicit synthetic native handles, and a
consistent fixture clock. Initial runs caught the SQLite Row/Mapping boundary,
a missing pending-cancel scope binding and the fixture's mixed real/future
clock; all were corrected without relaxing evidence requirements. Independent
review identified the replay and pre-manifest cut points now covered above.
The expanded tests also cover a NativeJob whose failed close has already made
it non-queryable, known mutex-close retry, unknown-close quarantine and settled
manifest validation on FINISHED replay. After cleanup begins, retries use the
immutable terminal receipt and exact native owners; they do not reacquire or
query a possibly closed Job/mutex. Each unsettled-manifest case has a separate
fixture, preserving the intentional fail-closed POLICY entry in the first case.

Full adaptive regression: 82 modules, 2,007 tests, zero failures/errors/skips in
233.928 seconds. Independent review then found a wrapper mutex close retry
that lacked unknown-outcome quarantine. The wrapper now tracks each exact
owner, tombstones successful closes and quarantines uncertain native effects;
only a positively known close failure permits retry. Six more regression
cases were added. The final affected launcher/retirement/store/P3-flow/wrapper
run passed 102 tests in 24.642 seconds, zero failures/errors/skips. The earlier
2,007-test full run does not include those six later tests. Commands and dirty
baseline dependencies are recorded in README.

Wrapper-host
automatic release/abandonment and operational CLI entrypoints remain item 4;
these source methods do not enable production adaptive or certify native gates.
