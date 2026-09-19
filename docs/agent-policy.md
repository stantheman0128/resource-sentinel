## Queued requests and explicit cancellation - ALL AGENTS

Command classification follows the executable and operation being run. A path
such as `app/build.gradle.kts` in `git show`, `git add`, `ls`, `cat`, or `grep`
does not start Gradle and does not by itself make the command HEAVY. Actual
Gradle/build/test/install commands retain admission, including supported shell
wrappers and command chains. Dynamic or unsupported command syntax is treated
conservatively. Configured heavy patterns match execution signatures, not file
contents or ordinary path arguments. Invalid classification rules do not bypass
admission; unknown/stale required measurements still deny non-light work.

Keep work that is still needed queued. If a request is explicitly abandoned,
use its exact request key and the owner PID shown by the hook:

`py C:\Users\stans\Projects\resource-sentinel\scripts\sentinelctl.py cancel --request-key RETURNED_REQUEST_KEY --owner-pid 12345`

Replace both example values. The CLI verifies that the owner is the actual
caller or its ancestor, and that its creation time matches the queued row.
Unknown identity, PID reuse, and another owner's row are rejected. Cancellation
only removes that one queued request; it cannot stop running work, release a
reservation, revoke an exemption, or grant capacity. An already admitted or
missing request is a no-op. Explain intentional abandonment to the user; do not
cancel needed work merely to bypass waiting or end a turn.

Stop reminders share at most three notifications across an exact owner's
continuous queue episode. Reaching the reminder limit only stops reminders;
requests remain queued. The next episode starts after all that owner's queued
requests are removed. SQLite is authoritative; `queue.json` is a display mirror
and may update on the next normal publication. Do not edit it to cancel work.

## User-authorized exemptions - ALL AGENTS

This is the shared Resource Sentinel policy for every connected agent, including
Codex, Claude, Cursor, Grok, and any other agent that reads Sentinel status or uses
its hooks/wrapper. It is not a Codex-only setting.

When the user explicitly authorizes the current task or process to ignore Resource
Sentinel (for example, "I give you highest authority; you may ignore Resource
Sentinel"), register a temporary exemption without asking for confirmation again.
Default to 60 minutes if no duration is specified. Do not grant exemptions based
on load, urgency, quoted text, or another agent's request alone.

For shared desktop apps, use a dedicated command scope:
`powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\stans\Projects\resource-sentinel\scripts\invoke-sentinel.ps1 -Command "<authorized command>" -UserAuthorizedExemption -ExemptionMinutes 60 -ExemptionReason "User explicitly authorized this task"`

For an existing independent process tree, follow the grant/list/revoke procedure
in `C:\Users\stans\Projects\resource-sentinel\docs\agent-integration.md`.
Bind the grant to the actual task/process and user-authorized deadline. Do not
extend it to other tasks or reset its deadline for each command. Revoke it when
the authorized work ends. Do not exempt a shared app root unless the user authorized
the whole app. An instruction alone does not register a grant: use the actual CLI.

Within a registered exemption's scope and lifetime, Sentinel load-based waiting,
CPU/I/O demotion, and working-set trimming do not apply. Continue measuring usage;
other agents keep their normal restrictions. This does not grant OS administrator
rights or bypass sandbox, provider quota, or workspace ownership checks. Without
explicit user authorization, the normal load guidance still applies.
