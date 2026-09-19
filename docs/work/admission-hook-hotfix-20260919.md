# Admission hook correction — 2026-09-19

Status: implemented, independently reviewed and verified on Windows. The hotfix
is synchronized to the maintained local hook source. Adaptive P1–P6 can resume;
this correction does not pass or bypass their native capability gates.

The protected main checkout remains at `0b2f378`; the implementation branch
started this continuation at `ed6521171cc5025460499dfb74e46f28083e2a5b`.
Private before copies, hashes and pre-existing diffs are under the implementation
worktree's ignored `.local-adaptive/hook-hotfix-20260919/`. They are not public
artifacts. Existing resource-v2, dashboard, policy and adaptive changes must not
be swept into this correction's commits.

## Required behavior

- Classify actual executable/verb rather than a builder's name in path/data
  arguments; preserve real heavy command admission through supported wrappers
  and chains. Unsupported/dynamic commands remain conservative.
- Add exact, caller/ancestor-birth-verified queue cancellation. Never delete
  another owner's row or touch running reservations/exemptions. Missing rows
  are idempotent no-ops; malformed or unknown identities reject.
- Share three Stop reminders across an exact owner's entire continuous queue
  episode. Stop never abandons work. Last queue deletion resets notification
  count only; retained owner/birth state prevents reimporting old JSON counts.
- Update the canonical policy and integration guide. Bootstrap markers and
  machine configuration remain unchanged.

## Verification

The existing Coordinator/hook baseline was first unable to access the normal
admission database inside the tool sandbox. Retried with approved normal wrapper
access, it queued for Commit capacity (1 CPU unit, 0.75 GiB RAM, 0 IO slots).
No tests ran during the failed sandbox attempt. Capacity denial is not a test
failure. Normal admission subsequently succeeded; no capacity exemption was used.

Windows / Python 3.13, all batches through the normal `invoke-sentinel.ps1`
wrapper with `-Priority P2 -CpuUnits 1 -RamGiB 0.75 -IoSlots 0`:

| Checkout | Python unittest modules | Result |
| --- | --- | --- |
| Protected main before edits | `tests.test_coordinator tests.test_hooks` | 23 pass, 0 fail, 0 skip |
| Implementation working tree | Hotfix batch below plus `tests.test_adaptive_coordinator` | 113 pass, 0 fail, 0 skip |
| Clean export of the staged files and HEAD | Same implementation batch | 113 pass, 0 fail, 0 skip |
| Maintained main source after narrow synchronization | Hotfix batch plus `tests.test_agent_policy tests.test_exemptions` | 110 pass, 0 fail, 0 skip |

Hotfix batch command:

```text
py -m unittest tests.test_command_classification tests.test_queue_cancel tests.test_stop_queue_reminders tests.test_hooks tests.test_hook_subprocess tests.test_coordinator
```

Coverage includes real CLI child-process cancellation, caller ancestry/birth,
foreign owner/PID reuse/unknown identity, admitted or missing requests, SQLite
compare-and-delete races, untouched reservations/exemptions, seven queue entries
sharing three reminders, concurrent Stop claims and legacy counter migration.
Real hook subprocesses with isolated USERPROFILE prove Gradle file reads do not
initialize the admission DB, while actual Gradle with missing telemetry queues.
Main-only regression tests also exercise the three-lease atomic cap and the
real Windows wrapper's cleanup using temporary stores.

Independent review found and resolved raw CMD single-quote parsing, fake
PowerShell `-Command ... -File` wrapper recognition, and executable `git grep`
pager options. The wrapper now declares `shell='cmd'`; Bash keeps POSIX parsing.
Unsupported syntax stays conservative. Review after the fixes reported no
remaining concrete finding within this hotfix's scope.

## Publication and operational boundary

- Commit candidates were constructed from HEAD plus this task's changes and
  tested as a clean export. Unrelated pre-existing dirty hunks remain unstaged.
- Main source synchronization required all eight existing file hashes to match
  private before copies. Seven new task-owned modules/tests were added. This
  does not copy the adaptive implementation into the live main checkout.
- The installed Claude gate/Stop loaders were read and verified to call the
  maintained repository hooks through `runpy.run_path`. Each invocation loads
  the corrected source; a collector restart is unnecessary for this correction.
- The normal runtime config hash and canonical bootstrap bytes remained
  unchanged. No global instruction sections or official Scheduled Tasks changed.
- No user queue entry was cancelled, no user exemption was created or revoked,
  and no CPU Job limit, trim, suspend/resume or work termination was performed.
  Test databases/profiles were isolated and fixture-owned. Normal test admission
  reservations used the wrapper's existing `finally` release path.
- Existing false-positive queue entries remain for their verified owner to
  abandon with the documented exact cancel command. No bulk cleanup is implied.
- Adaptive remains off/admission-only; native launch, recovery, overhead and A/B
  evidence are separate outstanding work, not outcomes of these passing tests.
