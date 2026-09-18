# P1 API contract preflight

Date: 2026-09-19. This is a read-only official-API cross-check, not a capability
result or replacement implementation plan. P0 baseline passed at 04:43:11;
no new Job control, Scheduled Task, launch or recovery experiment has run.

## Narrow clarifications to test

1. **Two command-length boundaries.** Plan section 4.3 must distinguish the
   PowerShell-to-Python Base64 transport from the Python-to-cmd payload.
   `CreateProcessW` permits 32,767 characters including the terminating NUL, while
   `cmd.exe` has an 8,191-character limit, also affecting expansion and inherited
   environment variables. A successful transport does not establish cmd support.
   Reject a known unsupported launch before user code; do not change shells,
   split/reassemble commands or retry an uncertain execution.
   Sources: [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
   [cmd command-line limits](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation).

2. **Absent standard handles.** `GetStdHandle` can return NULL or INVALID_HANDLE_VALUE.
   `STARTF_USESTDHANDLES` does not validate the values supplied to the child.
   `HANDLE_LIST` requires valid inheritable handles and `bInheritHandles=TRUE`;
   pseudo handles are not allowed. S2 needs separate console, pipe/file redirection,
   missing-input and missing-output cases. Test fixtures may explicitly open NUL or
   pipes. Production must preserve the command's I/O contract or reject before
   launch; it must not silently swallow output. Only close owned duplicates.
   Sources: [GetStdHandle](https://learn.microsoft.com/en-us/windows/console/getstdhandle),
   [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

These clarify unsupported inputs and evidence, without weakening a safety
invariant, adding a new launch fallback, or widening the MVP.

## Evidence still required from Windows

- JOB_LIST is supported from Windows 10 / Server 2016. Its composition with
  HANDLE_LIST, backing-storage lifetime, earliest child membership and restricted
  inheritance still need S1/S2 evidence; API availability alone is insufficient.
- The proposed disable binding remains flags 0 / rate 10000. Query must show
  ENABLE cleared and a saturated fixture must regain consumption. Do not require
  an unused union value to read back zero. Unsupported DFSS/rate-control results
  remain unsupported. Sources:
  [CPU rate structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information),
  [SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject).
- A foreign or unknown parent Job remains ineligible even if nested assignment
  succeeds. Parent limits can alter effective CPU capacity. A boolean result from
  `IsProcessInJob(process, NULL)` does not identify its owner. Do not add breakaway
  or parent spoofing. Sources:
  [Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs),
  [IsProcessInJob](https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob).
- CREATE_NEW_PROCESS_GROUP changes Ctrl+C behavior; hiding a window does not
  establish independent ancestry. Source:
  [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags).
- Scheduled Task RunEx may return S_OK without starting a disabled/non-demand task.
  EnginePID is not guardian readiness. Verify actual PID/birth, session/logon,
  parent chain and Job membership. Same account is not proof of the same
  interactive logon. Sources:
  [RunEx](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-iregisteredtask-runex),
  [EnginePID](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-irunningtask-get_enginepid),
  [TASK_LOGON_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type).
- Closing the last user handle is not proof that a populated Job is gone or that
  a CPU limit was undone. General completion notifications are not guaranteed
  substitutes for positive empty/query evidence. Preserve the plan's independent
  recovery owner, fencing and readback requirements. Source:
  [Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).

All P1 experiment results remain **not tested**, including native launch, CPU
effects, restore, Ctrl+C, subtree isolation and crash recovery.
