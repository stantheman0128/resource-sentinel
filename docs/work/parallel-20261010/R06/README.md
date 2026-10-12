# R06 binding constraint: scheduled task launcher

**Read this before touching, pinning, or "repairing" the `\ResourceSentinel` or
`\ResourceSentinelWatchdog` task action.**

## Rule

Both tasks must launch through a headless console host:

```text
Command:   C:\Windows\System32\conhost.exe
Arguments: --headless C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\stans\Projects\resource-sentinel\scripts\collect-scheduled.ps1"
```

The watchdog is identical except for `-File "...\scripts\watchdog.ps1"`.

Do not set the action back to `powershell.exe` directly, and do not go back to
`wscript.exe run-hidden.vbs`. Set by the user's direction on 2026-10-12 21:14 +08.

## Why

- The user's default terminal is Windows Terminal. When a task action starts
  `powershell.exe` directly, Windows Terminal takes over its console
  (`OpenConsole.exe -Embedding`) and opens a blank window on every run.
  `-WindowStyle Hidden` does not prevent this. With the collector on PT1M, that
  meant a popup every minute.
- The 2026-10-11 action-only update
  (`evidence/apply-collector-action-only-update-20261011T07xxZ.py`, proposal
  `evidence/collector-launcher-action-recovery-proposal-20261011T0738Z.md`)
  replaced the `wscript` launcher with direct PowerShell to close the orphaned
  child gap. Its review checked process ownership only. Nobody checked for
  visible windows, and the popups came back.
- `conhost.exe --headless` meets both requirements. Task Scheduler owns the conhost
  process, conhost stays alive for as long as its PowerShell client runs, and it
  creates no window. The orphaned-child concern from the 10-11 proposal stays
  addressed.

## Evidence (2026-10-12)

- Before the change, a live window/process watcher caught the following
  sequence. 21:12:01, Task Scheduler started `powershell.exe ...
  collect-scheduled.ps1`. 21:12:03, `OpenConsole.exe -Embedding` appeared.
  21:12:04, a new `CASCADIA_HOSTING_WINDOW_CLASS` window titled
  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` appeared. The child
  `collect.ps1` launched with `CreateNoWindow` opened no window.
- After the change, 6 minutes of watching (21:14 to 21:20) showed 6 collector
  runs and 1 watchdog run. There were 0 terminal windows and 0 `OpenConsole.exe`,
  and every PowerShell parent was `conhost.exe`. Both tasks returned
  `LastTaskResult=0` and `status.json` was 17 s old.
- A standalone test task with direct PowerShell did **not** reproduce the
  window. Only a live watcher on the real tasks over 2 or more scheduled cycles
  counts as evidence.
- Pre-change task XML: `../../task-action-backup-20261012/`.

## Impact on R06 preflight and runner pins

`evidence/derive-r06-preflight-exact-task-action-20261012T1755+0800.ps1`
(lines 47-53) and
`evidence/build-r06-ready-runner-exact-task-action-20261012T1757+0800.ps1`
(lines 80-83) pin `task_action_pinned` / `actionStable` to the direct
`powershell.exe` command and arguments. Those pins are now **stale**:

- A preflight or runner failing on `task_action_pinned=false` or an unstable
  action is expected. It is **not** grounds to change the scheduled task.
- Re-derive the expected command as `conhost.exe` with the exact arguments
  above, through the normal review/pin chain, before running the harness.
- The process that runs `collect-scheduled.ps1` is still `powershell.exe` with
  the same arguments, so command-line matching (for example
  `C:\ProgramData\RSGuard\guard.ps1`) is unaffected. Its parent is now
  `conhost.exe` instead of `svchost.exe`.

## Changing the launcher in the future

Any proposal to change either action needs explicit approval from the user and
must show, with a live watcher on the real tasks over 2 or more scheduled
cycles, that no visible window appears. A review that checks ownership alone is
not sufficient.
