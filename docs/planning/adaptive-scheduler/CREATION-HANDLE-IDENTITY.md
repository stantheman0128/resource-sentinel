# Retained creation-handle identity

This closes a native identity prerequisite for lifecycle registration. It does
not implement the continuous admission owner, pass P1 or promote P3-P6. The
existing unknown-parent and continuous-admission gates remain closed; adaptive
remains off.

## Problem and consumer

The test launcher retains the process handle returned by `CreateProcessW`, but
previously verified only PID and integer creation FILETIME. The lifecycle
contract also requires the target's logon identity. Reopening a PID after a fast
exit would discard the stronger original-object evidence and introduce a reuse
race.

`VerifiedProcess.duplicate_from_handle()` now duplicates that borrowed process
handle with query/synchronization rights, without inheritance or
`DUPLICATE_CLOSE_SOURCE`. It reads PID, full FILETIME and target logon from the
same kernel object, then checks the expected PID and logon. The original handle
remains owned by the caller on success and failure. The expected fields are
consistency checks, not proof of creation provenance or allocation authority.

The real `launch_in_job()` post-create check consumes this through
`ProcessHandle.full_identity()`. The existing two-field `identity()` diagnostic
format remains compatible with fixtures. A failure after successful creation
still raises `LaunchOutcomeUnknown`, retains the original process and does not
retry the command. A failed duplicate close also retains cleanup ownership for
an explicit retry through the existing process cleanup path. No unknown identity
is converted into a verified process.

Both S3 test callers now adopt the exception-held process. The actor uses its
existing cooperative stop signal and preserves both handles when exit is
unverified. It does not enter the intentional crash path or retry the command.

## Native preflight evidence

On Windows 11 build 26340 / x64 Python 3.13.3, normal Sentinel P2 admission covered
eight sequential, isolated commands: four immediately returning commands and
four commands that slept for 0.25 seconds before returning. Every original
`CreateProcess` handle was retained through a signaled natural exit.

- All eight commands exited naturally with code 0.
- Full PID/FILETIME/target-logon reads succeeded both immediately and after exit.
- All eight identities were unchanged across those observations.
- No Job was created and no CPU, memory, priority or I/O control was written.
- No existing workload was stopped and no PID was reopened.

This bounded observation establishes behavior on this tested host. It does not
turn an undocumented guarantee about every Windows/token configuration into an
assumption: any failed full identity read remains unknown. Retaining a process
handle or observing root exit does not establish Job empty or release capacity.

## Validation

The final clean exported source tree was
`4c898cad4a2a6885de3eb7c22d885dce1675bcb9`. Its targeted regression ran on the same
Windows host through normal Sentinel P2 admission (1 CPU unit, 0.75 GiB RAM,
0 I/O slots), with `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0`:

```text
py -X utf8 -m unittest tests.test_adaptive_identity tests.test_adaptive_created_identity tests.test_adaptive_created_identity_native tests.test_adaptive_continuous_admission tests.test_adaptive_admission_context tests.test_adaptive_native_cancel tests.test_adaptive_native_ipc tests.test_adaptive_ipc tests.test_adaptive_s1_gate tests.windows.test_adaptive_launch_compatibility.LaunchLengthContracts
149 passed; 0 failures/errors/skips; 5.797 seconds
```

The change adds 25 test methods, including three native identity cases that
create six sequential, self-ending commands in isolated temporary directories.
They verify fresh duplication after an already-signaled exit, same-object full
identity, mismatch rejection without closing the original, and noninheritance.
Backend PID reopening is forbidden during those native checks. The retained
duplicate's DEAD observation is verified; the short-command case does not claim
a guaranteed observed ALIVE-to-DEAD transition.

Portable tests exercise the actual launcher and both S3 callers through a fake
ABI, duplicate cleanup ownership, original exception preservation, and unknown
exit retention. Fixture cleanup errors retain process/thread handles and block
every subsequent launch, including subsequent subtests.

The first clean run had 146 tests, zero assertion failures and two cleanup errors
(`WinError 32`): S3's SQLite fixture transaction context did not close its
connection. The fixture now preserves commit/rollback semantics while closing
the connection on every exit; two added tests check both paths. This was a real
test-fixture lifetime bug, not an expectation change or production DB migration.
That revised candidate passed 148 tests. Final review then added the actor's
unverified-exit retention test, yielding the final 149-test pass above. Failure
logs and the intermediate candidate trees remain local.

No native Job/control experiment ran, no capability gate was unlocked, and no
exemption was granted. The preflight observations and native identity cases
cannot substitute for S1/S2/S3 or continuous coverage. Ancillary token/buffer
cleanup limitations outside the duplicate-handle change remain separate work.

## Official contracts and remaining work

[Process handles remain valid until closed](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
and [DuplicateHandle references the same object](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle).
The duplicate uses the rights required by
[GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
and [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken).
The latter does not explicitly promise successful token queries after every
process termination, which is why the native observation and fail-closed error
path are both required.

Still missing for full native lifecycle: retained Job ownership, durable recovery
manifests, effective legacy-writer exclusion, authenticated lifecycle mutation,
launch sealing and settlement through restore/readback/Job empty. These must be
consumed by the real runner before continuous admission can be declared ready.
This identity change neither supplies those contracts nor changes daily runtime.
