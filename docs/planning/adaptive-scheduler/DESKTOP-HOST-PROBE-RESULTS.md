# Desktop host probe: foreign child Job remains unsupported

Status: **P1 native capability gate remains blocked. No CPU control was applied.**
This is a test-host experiment, not a production launcher or a supported fallback
for wrapper commands. The formal foreign-parent/unknown-denominator rejection
remains unchanged. Safe admission-only accounting work is a separate deliverable.

## Observed sequence

On Windows 11 build 26340, x64 Python 3.13.3, the read-only desktop preflight
confirmed that the actual desktop Explorer was non-elevated, medium integrity,
in the caller's user/logon/session, and outside any Job. The first preflight had
failed closed because its TokenElevation size query returned Win32 24. That
original evidence was retained; fixed DWORD queries and regression tests were
added before the second preflight established the desktop candidate.

The 52 pure desktop preflight, launch-protocol and child-fixture tests then
passed. An independent static review found no must-fix before the single
normally admitted native experiment. Neither result was treated as native
launch/control capability proof.

The test used the actual desktop `FindWindowSW` / `IShellBrowser` folder view's
`Application` / `IShellDispatch2.ShellExecute`. It dispatched only the fixed
Pythonw read-only fixture with a fresh isolated nonce and a 15-second ticket.
There was no parent substitution, breakaway, elevation, Job creation, process
control, test Scheduled Task, runtime configuration change or dispatch retry.

| Evidence | Observation |
|---|---|
| Desktop preflight | Actual Explorer: same user/logon/session, medium integrity, non-elevated, `in_any_job=false` |
| COM invocation | Returned successfully; COM thread completed cleanup |
| READY / parent ACK | No READY was published; no ACK or independent held-child validation occurred |
| Child `done.json` | `observation_unknown`, reason `unsupported_self_identity`; self-report says session 1, medium integrity, non-elevated, **`in_any_job=true`** |
| Controller result | `launch_outcome_unknown`, `candidate=false`, `child_verified=false`, `child_exit_verified=false` |
| Subsequent scoped exit check | Read-only `OpenProcess` for the recorded fixture PID returned `ERROR_INVALID_PARAMETER` (87): that original PID was absent |

The child report is explicitly **self-reported and unverified**, since the
fixture rejected its host before the parent could hold its exact handle. Its
later absence confirms no process still occupied that PID at the scoped check;
it does not establish an earlier parent-verified identity, successful handshake,
exit code, or CPU denominator. COM success alone establishes none of those.

The known non-Job Explorer therefore did **not** establish a usable independent
test host. The source or owner of the child's reported Job was not identified.
Do not infer which Windows component assigned it, disregard it, or weaken the
foreign Job rejection to continue control tests.

## Diagnostic improvement and evidence preservation

The controller now reads a bounded `done.json` even when READY is absent and
exports a sanitized `child_self_report_unverified` diagnostic. It leaves all
candidate, identity and exit gates unchanged. Nonce/schema mismatch, oversized
or malformed JSON fails closed; arbitrary child error text is not published.
The three added pure regressions cover this missing-READY case, an unverified
ACK claim, privacy filtering, and oversized diagnostic input. These additional
regressions were then verified in a separate normally admitted rerun: all
**55 pure desktop tests passed**, 0.344 seconds, no skips. The native dispatch
was not repeated. These regressions were not part of the earlier 52-test result.

Original local evidence is untouched:

- `.local-adaptive/resume-host/desktop-preflight-01.json`
- `.local-adaptive/resume-host/desktop-preflight-02.json`
- `.local-adaptive/resume-host/e2b07d9dbf3f3421524d313cfc99ca46/`
- `.local-adaptive/resume-host/desktop-launch-e2b07d9d-exit-postcheck.json`

The nonce directory retains request, original controller result and child done
records. Public documentation omits user/logon identifiers and private paths.
No attempt was made to reconstruct an ACK or rewrite the original result with
new diagnostic behavior.

## Gate and next action

Codex execution, the isolated same-user Scheduled Task, and now this single
Explorer-dispatched fixture have not established a supported foreign-Job-free
child host. Do not retry this dispatch, add a breakaway/PCA/parent-spoofing route,
or claim S1/S2/S3 CPU-effect/recovery acceptance. Continue the authorized A /
admission-only accounting work; retain adaptive off. Active-control promotion
still requires a separately verified compatible Windows host and the formal
native capability/recovery gates.

Ticket and ACK checks bound the cooperative protocol under normal scheduling;
synchronous native or filesystem calls can still block. They are not an
OS-enforced maximum process lifetime.

## Instrumented continuation: identity and exit verified, control unsupported

On 2026-09-19 at approximately 20:10 local time, the revised observation protocol
was exercised once after independent static review and **85 pure tests passed**
(0 failures, 0 skips). This was a separately instrumented diagnostic to resolve
the missing-READY evidence gap; it did not repeat the old unchanged probe or
relax enrollment. The original nonce/evidence above remains untouched.

Command, through the normal P2 admission wrapper with 1 CPU unit, 0.75 GiB RAM
and no heavy-I/O slot:

```text
py tests/windows/probe_adaptive_desktop_launch.py --output-directory <implementation-worktree>/.local-adaptive/resume-host --dispatch-read-only-probe
```

Private evidence is under nonce `e49553251a188e69af43eef273e26292` in that output
directory. The fixed child now completes READY and parent-held exact identity
verification before collecting diagnostics. The parent sends ACK, verifies the
same handle's natural exit and checks the completed report.

| Evidence | New observation |
| --- | --- |
| Identity / exit | `child_verified=true`, `child_exit_verified=true`, child exit code 0 |
| Protocol | `observation_completed=true`, no controller errors, COM thread completed |
| Control gate | `candidate=false`, `control_eligible=false`, `unsupported_foreign_or_unknown_job` |
| Immediate Job self-query | Membership present; CPU flags 0; extended limit flags `0x800`; UI flags 0 |
| Group self-query | Group 0 affinity mask 4095; immediate Job data only |
| Process lineage self-query | First parent matches the independently held desktop identity and is outside a Job; relation/birth rechecked; further parent read unknown |
| Mutations | Zero process-control writes, Job creation, CPU caps or production Task changes; no dispatch retry in this invocation |

The parent independently verifies the child identity, Job membership and exit.
The additional Job-limit and lineage details remain explicitly labeled child
self-reports; they are bounded diagnostics, not complete native capability proof.
Only the first process-parent link was observed; the full process ancestry is
unknown, and process ancestry is not Job ancestry.

`QueryInformationJobObject(NULL)` queries the calling process's **immediate** Job;
it does not reveal the entire Job hierarchy. A zero immediate CPU flag therefore
does not establish the inherited denominator or remove the formal foreign-Job
gate. See [Microsoft's API contract](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)
and [nested Job behavior](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).
No source/owner of the external Job was established or guessed, and no breakaway
flag, altered token or parent substitution was used.

This closes the earlier identity/exit diagnostic gap. It does **not** pass P1 or
authorize S1 CPU control. The separate live demand-floor continuity prerequisite
is recorded in [CAPABILITY-RESULTS.md](CAPABILITY-RESULTS.md). Stop further unchanged
desktop dispatch attempts; continue safe admission-only implementation until a
supported host and continuous test admission coverage can be established.
