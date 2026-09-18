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
delivered. P1's exit gate failed, so ordered P2–P6 implementation/promotion is
held. The existing admission-only behavior remains the operational fallback;
this does not claim P2 common accounting has been delivered. Production adaptive
remains off. No new CPU restriction was applied or represented as withdrawn by
closing a handle.

Next: supply a verified host outside an unknown parent Job and repeat the host
probe first. Then, through normal admission on that host, set explicit native
opt-in and an isolated evidence directory and run S1/S2/S3 in sequence. S1 on
this topology needs the five-unit CPU estimate described above, not the one-unit
preflight reservation. If no compatible host is available, retain these failure
results and do not proceed to active control or weaken the formal plan.
