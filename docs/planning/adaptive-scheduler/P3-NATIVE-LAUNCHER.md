# Native launcher implementation and current gate status

2026-09-20. This work extracts the actual atomic process-creation operation into
the production package and connects the existing Windows experiment consumers
to it. It does not promote the serial S1 test owner into a production guardian.
Adaptive remains off; no daily runtime deployment is part of this change.

## Why P3-P6 are not complete

There are separate implementation and environment gaps. Treating every missing
component as a Windows capability failure was inaccurate.

| Phase | Verified scope | Remaining exit evidence |
|---|---|---|
| P0 | Baseline reconciliation and protected working-tree inventory | Reconcile any future runtime cutover against the then-current live tree |
| P1 | Isolated test code, retained identity, native machine counters and power notification smoke checks | Real S1/S2/S3: an eligible launcher context and continuous host admission authority |
| P2 | Common projection, exact allocation binding, lifetime retention and lifecycle transaction tests | Complete native ownership integration and coordinated live writer loading |
| P3 | Control-slot/exemption transactions, source collector handoff, S1 owner/recovery consumers, shared native launch operation | Production guardian/supervisor/wrapper integration, loaded-writer exclusion and native recovery gates |
| P4 | Machine sampler implementation | Complete bounded Job sampling/shadow consumer and measured observer cost |
| P5 | Fault experiment scaffolding and source-level failure tests | Single isolated native canary and real fault/recovery matrix |
| P6 | Formal acceptance criteria | Paired real-command A/B results and limited-release acceptance |

Rows marked with remaining evidence are not phase passes. Unit-test totals,
successful imports and source presence do not prove native control or recovery.

## Concrete host prerequisites checked

A read-only check of the daily authority at the start of this slice found no
managed-execution, adaptive-runtime or control-slot schema. Its direct allocation
schema also lacks the candidate's lifecycle binding and writer revision fields.
The daily admission implementation still ages pending demand after its grace
period, and its control writers do not load the candidate's shared mutation
boundary. The 35 monitored daily source paths and configuration were unchanged
from the recorded baseline. No schema migration was performed.

Consequently, an isolated ledger on this same host cannot certify that all real
admissions retain the managed demand floor. Source updates in this worktree do
not replace already loaded daily writers. A real coordinated runtime cutover or
a separate test host whose whole admission/writer cohort uses the candidate is
required. The original instruction explicitly excludes changing daily runtime.

Separately, the already recorded command-host, test Scheduled Task, exact
Explorer-dispatched pythonw child and existing CI observations failed the
unknown-parent-Job preflight. The Explorer child was successfully identified and
observed to exit naturally; the result was not a missing-handshake false alarm.
No repeated host probe was run for this source slice. See
[desktop evidence](DESKTOP-HOST-PROBE-RESULTS.md) and
[CI evidence](CI-HOST-PROBE-RESULTS.md).

Knowing only the immediate Job's flags cannot certify the full inherited CPU
denominator. No breakaway, parent substitution or unsupported host exception is
introduced. A newly supplied compatible Windows execution context must still
pass exact parent/child checks and the real admission and S1/S2/S3 gates.

## Implementation boundary

The common native operation uses `CreateProcessW` with `JOB_LIST` and an explicit
`HANDLE_LIST`. It preserves the original command line and transfers ownership of
the returned process into an exact-handle carrier. The test adapter retains its
existing opt-in and supported-host checks; production code imports no test code.
There is no alternate spawn after a failed or uncertain attempt.

Thread, standard-handle duplicate and attribute-list cleanup belong to the same
attempt. A failure after process creation cannot be acknowledged as a successful
launch or discard the process needed for reconciliation. Closing these handles
does not establish Job empty, restore a cap or release an allocation.

Exact-identity cleanup uses the same distinction: a confirmed native `FALSE`
can retain ownership for a later retry, while an interrupted call with an unknown
outcome quarantines the numeric handle. Unknown completion must not cause a
second close or a query against a potentially reused handle. The original owner
remains reachable for reconciliation. This change does not extend that protocol
to every security-token or native-buffer allocation elsewhere in the package.

The in-memory launch transport uses the existing typed resource/role/priority
contracts, strict JSON and one UTF-8 Base64 argument. It checks the entire quoted
Python-host command line in UTF-16 units, including the terminating NUL, before
launch. The separate cmd limit is checked without splitting or rejoining the
workload command. Base64 is transport encoding, not encryption or authority;
raw payloads and paths remain excluded from diagnostics and object reprs.

S2 consumes the same command builder and host-length checks. Its synthetic
authorization envelope remains test-only; passing transport validation does
not authorize a fixture launch or establish PowerShell/stdio compatibility.

The implementation follows the documented
[CreateProcessW contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[attribute-list contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
and [handle cleanup contract](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).
These API contracts do not substitute for actual host capability measurements.

## Validation

Windows, Python unittest, isolated Git-index exports. Each run used the daily
`scripts/invoke-sentinel.ps1` admission wrapper at P2 with CPU 1, RAM 1 GiB and
I/O 0; no exemption was used. `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` throughout.
The private runner executes the listed unittest modules against the exact export,
not the dirty implementation worktree. Reproduce the module commands below from
a clean checkout through the host's normal admission wrapper.

| Candidate tree | Command scope | Result |
|---|---|---|
| `16418b22883e7159ad9ad6a10170abc8133fe4d4` | Transport, S2 length contracts and continuous-admission contracts | 40 passed; 0 failures/errors/skips |
| `02bb161bfd6e8a975a3af4f39a9caaea3c567ebd` | Native launcher, exact identity, execution ownership, recovery, control authority and admission consumers | 225 run: 223 passed, 2 errors; 0 failures/skips |
| `7004786b3c4ad6c589b35c9053acacf06a0d3a90` | Affected legacy native consumer after fixture correction and an added regression | 21 passed; 0 failures/errors/skips |

```text
py -m unittest tests.test_adaptive_launch_spec tests.windows.test_adaptive_launch_compatibility.LaunchLengthContracts tests.test_adaptive_continuous_admission

py -m unittest tests.test_adaptive_native_launcher tests.test_adaptive_native_launcher.NativeLauncherBindingSmoke.native_bindings tests.test_adaptive_identity_cleanup tests.test_adaptive_identity tests.test_adaptive_created_identity tests.test_adaptive_execution_owner tests.test_adaptive_s1_owner_integration tests.test_adaptive_recovery tests.test_adaptive_control_authority tests.test_adaptive_legacy_native tests.test_adaptive_managed_admission tests.test_adaptive_continuous_admission

py -m unittest tests.test_adaptive_legacy_native
```

The two errors exposed a legacy test fixture that raised an unspecified cleanup
exception while its assertions expected a retryable native `FALSE`. The fixture
now identifies that known failure explicitly; both retry assertions remain.
An additional consumer test checks that an unknown close cannot reclose the same
handle or re-enable a legacy writer. Only that test file changed between the
second and third trees. Production source and the other tested modules are
identical; no fresh combined-suite pass is claimed or overlapping totals added.

The Windows-specific checks here cover actual DLL bindings/ctypes pointer layouts,
read-only current-process identity, and an isolated managed-admission smoke test
using the real policy mutex and fixture capacity. They do not launch a workload
or establish CPU-control capability. Most fault paths use deterministic fake API
outcomes; actual S1/S2/S3, guardian crash recovery, observer cost and A/B remain
unverified. The first sandbox attempt could not open the daily admission DB and
ran no tests; the same normal wrapper subsequently ran with filesystem access.

After all three runs, none of their reservations remained. All seven staged
source/test files matched their tested export, all 35 monitored daily source
files and the daily config matched the preserved baseline. No test Job, CPU cap,
workload fixture process or Scheduled Task was created for this slice, so there
is no test CPU limit to withdraw. Raw logs and daily-state fingerprints stay in
the private work directory. Documentation-only edits after testing do not change
the tested code. No deployment or phase promotion is claimed.
