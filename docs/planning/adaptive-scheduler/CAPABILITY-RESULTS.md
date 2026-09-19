# P1 capability evidence — 2026-09-19

Status: **P1 blocked by unsupported launch hosts; S1/S2/S3 are not verified.
No capability allowlist exists.**
P0 passed on the reconciled local baseline. Adaptive production remains off.
This is an execution checkpoint, not a replacement plan.

## Environment and scope

Windows 11 build 26340, x64 Python 3.13.3, 12 logical processors in one group;
Windows PowerShell 5.1 and the already installed pwsh are available. Both sandboxed
and ordinary Codex command hosts report existing Job membership. Ownership and
the parent denominator are unknown. These hosts are ineligible for managed
launch; no breakaway, suspended launch, or parent spoofing was attempted.

The bounded alternative is one nonce-named, current-user, limited Interactive
test Scheduled Task. It runs a read-only child that reports native process birth,
parent PID, session, authentication LUID and Job membership. Host candidacy does
not establish Job launch, CPU effect, recovery or an 8-second recovery guarantee.
Only the task created by that invocation may be removed. Cleanup uncertainty
must fail the probe. No existing production task may be modified.

## Implemented test-only scope

| Artifact | Evidence it is designed to collect | Current evidence |
|---|---|---|
| `tests/windows/adaptive_win32.py` | 64-bit ABI, actual logon ACL, owned named Job, exact held identity, JOB_LIST/HANDLE_LIST, CPU Query/Set/disable, mutex fencing | Static review only |
| `test_adaptive_job_capability.py` and `adaptive_cpu_worker.py` | Self-deadline, foreign-parent rejection, 10 create/cap/reopen/restore rounds, 30-second CPU windows | Not run |
| `test_adaptive_launch_compatibility.py` and `adaptive_spawn_tree.py` | Fixed cmd/PS/pwsh/stdio/Unicode/exit cases, Ctrl+C, fast exit, surviving children, fixture collector subtree | Not run |
| `test_adaptive_recovery_capability.py` and `adaptive_recovery_actor.py` | Eight formal fault points plus hang/wrapper-loss/grant-before-cap/audit-lock, 10 repetitions each | Not run |
| `probe_adaptive_host.py`, `probe_adaptive_task_host.ps1` | Bounded read-only alternative host and owned task cleanup | Executed; unsupported parent Job; task removed |

Native tests require explicit opt-in and an isolated evidence directory. Ordinary
discovery skips native cases; those skips cannot count as capability passes.
Recovery fixtures use a test lease/SQLite protocol, not the production store or
IPC. Their output explicitly leaves independent supervisor and S1 consumption
evidence outstanding. S2's collector fixture does not prove a production adapter
or supervisor is integrated.

Lightweight syntax validation passed for all eight Python files using `ast.parse`
(no imports or fixtures) and the Scheduled Task probe using the PowerShell parser.
These are syntax results only, not native capability or recovery evidence.

The initial S1 draft unnecessarily required an uncapped workload occupying 90%
of all N processors. The formal plan requires saturation above the tested cap,
not full-host saturation. S1 now fixes `ceil((target+tolerance+0.25)/0.9)` busy
workers before all ten rounds. For this 12-processor host that is four workers,
with an accurate conservative admission request of five CPU units. The rate
denominator remains N=12 and target remains three units. The uncapped baseline
must reach 3.6 units; restored consumption must both regain 90% of its own baseline
and exceed 3.55 units, clearly outside the capped acceptance band of 2.7–3.3.
All 30-second windows, round counts and safety invariants are unchanged. This
removes an extra test assumption; it does not change the formal success criteria
or the live eight-unit CPU admission budget.

## Admission interruption evidence

Two queued requests exited before launching their test/probe commands because
the existing live Coordinator could not acquire `BEGIN IMMEDIATE` and its timeout
cleanup also encountered `sqlite3.OperationalError: database is locked`.
Read-only queries identified each exact orphan; the existing `wait-existing`
command with that request key, owner and timeout zero cancelled one row each.
Other agents' queues, reservations and grants were untouched. This was an
admission infrastructure failure, not a failing Windows capability test.

The follow-up disk/display suites are submitted as one sequential normal request
(P2, 1 CPU unit, 0.5 GiB RAM, 0 heavy-I/O slots). No exemption or policy change is
used. Private logs and manifests remain in `.local-adaptive/`.

## Executed results and blocker

Normal admission succeeded for the follow-up preflight at 05:32. The following
commands ran on this Windows host, with native spike opt-in explicitly set to 0:

| Command | Result |
|---|---|
| `py -m unittest discover -s tests/windows -p 'test_adaptive_*.py'` | Exit 0, unittest reports 13 tests and 12 skip records. Two pure command-length checks ran; native S1/S2 cases and S3 class setup were skipped. A class setup skip is counted differently from a test method, so these totals must not be interpreted as a Windows pass rate. |
| `powershell -NoProfile -ExecutionPolicy Bypass -File tests/windows/probe_adaptive_task_host.ps1 -OutputDirectory .local-adaptive/p1` | Exit 2: `unsupported_parent_job_present`; 05:32:21–05:32:25 |

Both the caller and task child produced valid 64-bit native observations. They
matched Windows session and authentication LUID. Both reported `in_any_job=true`.
The temporary task itself finished with exit 0; the outer probe correctly
rejected its host candidacy. Task cleanup returned `removed_verified`, without
needing Stop-ScheduledTask. Job/CPU control writes: **zero**. Production Scheduled
Task modifications: **zero**. The task contained only read-only metadata queries.

The two observed launch paths therefore cannot establish a known CPU denominator
or satisfy the formal foreign-parent gate. No existing Windows CI workflow was
found in the checked repository. A compatible independent host is an external
prerequisite; adding a new service/VM/CI platform, allowing an unknown parent Job,
using breakaway or parent spoofing is not a justified workaround for this gate.
The native S1/S2/S3 matrix, Ctrl+C, cap effects, recovery timings, independent
supervisor and A/B remain unverified. The active-mode gate has not passed.

Private evidence: `.local-adaptive/p1-preflight-20260919-053219/` and its referenced
nonce directory in `.local-adaptive/p1/`. Public results omit authentication
identifiers and private process/session labels.

## Promotion and next action

P0 is complete; P1 test-only implementation and the host rejection evidence are
delivered. P1's native exit gate has not passed. The earlier blanket hold on all
P2 work was too broad: formal sections 2.1, 10/P1 and 13.4 explicitly permit the
independent admission/lifecycle/shared-accounting deliverable A. That safe P2-A
work is now being implemented and verified in the isolated implementation tree.
Native enrollment and P3–P6 promotion remain gated; L1 evidence does not satisfy
them. Production adaptive remains off. No new CPU restriction was applied or
represented as withdrawn by closing a handle.

Next: supply a verified host outside an unknown parent Job and repeat the host
probe first. Then, through normal admission on that host, set explicit native
opt-in and an isolated evidence directory and run S1/S2/S3 in sequence. S1 on
this topology needs the five-unit CPU estimate described above, not the one-unit
preflight reservation. If no compatible host is available, retain these failure
results and do not proceed to active control or weaken the formal plan.

## Resume: read-only desktop candidate, 2026-09-19

`probe_adaptive_desktop.py` inspects only its own process and the actual
`GetShellWindow` owner, holding query/synchronize handles while checking full
creation FILETIME, image, token, session and Job membership twice. It publishes
comparison results rather than private SID/logon identifiers. No arbitrary PID,
dispatch or process-control operation exists in this preflight.

The first native attempt returned unknown (`GetTokenInformationSize_20`, error
24). The fixed-size DWORD token classes now use their documented four-byte
query buffer; variable-size queries reject changed result lengths. All 17 pure
preflight tests pass. A second native observation is valid: the existing system
Explorer is unelevated medium integrity, belongs to the same user/logon/session,
and is outside a Job. The admitted caller remains inside a Job. This result is
only `candidate_desktop_not_launch_verified`, not an allowance for ordinary
wrapper hosts or evidence of CPU/recovery capability. Both attempts performed
zero dispatches and zero control writes. Private evidence is retained under
`.local-adaptive/resume-host/`.

The actual desktop shell view's automation interface was then tested once,
through normal admission, using only a fixed read-only self probe. All 52 pure
desktop probe tests passed before dispatch. COM returned success, but the child
did not reach the verified READY/ACK path. Its private diagnostic reports
`unsupported_self_identity` and `in_any_job=true`. This self-report does not
establish independently verified launch success; the outer result correctly
remains `launch_outcome_unknown`. A subsequent query-only OpenProcess check for
the exact test PID returned error 87 (absent); nothing was killed or retried.

Thus this third explored host path also fails to establish the required
outside-foreign-Job child. No Job was created, no CPU control was written, and
no production Task or launch entry changed. The code remains a test-host probe,
with no breakaway, parent spoofing or production fallback. Detailed sanitized
evidence is in [DESKTOP-HOST-PROBE-RESULTS.md](DESKTOP-HOST-PROBE-RESULTS.md).
P1 native gates, P3–P6 promotion, real cap effects and recovery remain unverified;
the safe P2-A work continues independently under the formal fallback.

## Continuation: test verdict and admission coverage corrections

Following the separately completed hook correction (`56fc1e6`), native tests were
audited before any further control experiment. Three test-evidence gaps were
corrected without changing CPU effect thresholds or claiming a native pass:

- S1 now requires same-run successful fixture self-stop, empty named Job
  reopen/set/query/disable binding, and foreign-parent rejection before its
  effect workload. Cleanup and evidence publication must complete before a stage
  passes. A failed, skipped, reordered or selected-only stage blocks later native
  calls even under unittest's default non-failfast runner. The documented command
  also uses `-f`. The empty Job check is API restoration evidence, not CPU effect.
- S3 guardian-loss time is measured conservatively from the actor's pre-exit
  interrupt-time marker (or the test guardian's pre-termination-request marker)
  to the first independently recorded disabled Query ACK. Observer resumption
  cannot restart this clock. The measurement is an upper bound around process
  death, not a claimed exact kernel death timestamp.
- S3's original 120-second outside deadline now determines the final verdict
  using interrupt-time and monotonic elapsed, including cleanup. Safety cleanup
  may continue after expiry; it cannot convert that case into a pass.

Normal admission on Windows/Python 3.13.3 ran
`py -m unittest tests.test_adaptive_s1_gate tests.test_adaptive_recovery_timing`:
**21 passed, 0 failed, 0 skipped**. Native spike opt-in was explicitly zero.
These are L1 tests only; no Job was created or restricted.

There is also a separate execution prerequisite: the actual live Coordinator
still ages pending CPU/RAM out by `created_at` grace. P2-A's continuous floor is
implemented in the isolated branch, not deployed. The live wrapper prints its
exact reservation ID but does not pass a verified coverage lease to the child;
repeat admission of the same key extends expiry, not the floor's created-at age.
Consequently, one ordinary reservation is not demonstrated to cover the full
ten-round S1 experiment through Query-confirmed restore and Job empty.

Do not run that long control experiment against the current live path. Breaking
it into roughly 90-second measurement rounds alone is also insufficient: setup,
scheduling stalls, failure and cleanup can cross the grace boundary. A future
bounded runner must prove exact coverage for the entire controlled lifetime, or
use an actually independent test host with its own correct admission accounting.
No runtime grace change, nested-reservation workaround, P2 deployment, exemption
or different local data directory was used to evade this prerequisite.

One subsequent, revised read-only desktop diagnostic completed the previously
missing held-child handshake and natural exit: `observation_completed=true`,
`child_verified=true`, `child_exit_verified=true`, exit code 0, zero control
writes. The independently observed child remains in a foreign/unknown Job, so
candidate/control eligibility remain false. Immediate CPU flags 0 do not prove
the inherited denominator. The 85 pure diagnostic tests passed first; full
details and bounded-query limitations are in the instrumented-continuation
section of [DESKTOP-HOST-PROBE-RESULTS.md](DESKTOP-HOST-PROBE-RESULTS.md).
