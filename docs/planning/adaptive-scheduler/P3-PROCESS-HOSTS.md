# Process hosts and the production host authority

2026-09-21. Until now every adaptive component was a library that only a test
constructed. This adds the four process hosts that can run them, plus the live
authority they ask before anything happens. Nothing here is installed,
registered or scheduled. Adaptive stays off, and no file outside this list
changed.

New files:

- `sentinel/adaptive/host_authority.py`
- `sentinel/adaptive/guardian_host.py`
- `sentinel/adaptive/supervisor_host.py`
- `sentinel/adaptive/wrapper_host.py`
- `tests/test_adaptive_host_authority.py`
- `tests/test_adaptive_guardian_host.py`
- `tests/test_adaptive_supervisor_host.py`
- `tests/test_adaptive_wrapper_host.py`

## The authority behind every check

`HostAuthority` (`sentinel/adaptive/host_authority.py:176`) replaces the two
defaults that refused everything: `_UnavailableAuthority` in
`sentinel/adaptive/guardian.py:32` and `_UnavailableReadiness` in
`sentinel/adaptive/launcher.py:55`. Each method is a live read. None of them
reads a configuration flag, a cached receipt or a serialized readiness field,
and none returns success from a constant.

| Check | Method | Authoritative source |
| --- | --- | --- |
| Host capability | `assert_ready` at `host_authority.py:200` | `read_host_capability` at `host_authority.py:123`, which calls `IsProcessInJob`, `GetActiveProcessorGroupCount`, `GetActiveProcessorCount` and `GetProcessAffinityMask` on every call |
| Coverage freshness | `assert_covered` at `host_authority.py:207` | the ledger snapshot read through `_coverage_read_transaction`, then `validate_active_allocation` from `sentinel/accounting.py`, then the bound reservation lease in `_lease` at `host_authority.py:405` |
| Legacy writer exclusion | `assert_excluded` at `host_authority.py:232` | `writer_obligations_present` for the fence, and `_registry_locked` from `sentinel/adaptive/legacy_writer.py` for the live protected identity set and Job name list, read under the POLICY guard the caller already holds |
| Wrapper launch readiness | `assert_launch_ready` at `host_authority.py:285` | the capability preflight again, `LifecycleStore.query` against the pinned ledger path, and `LifecycleStore.assert_admission_covered` |

The capability preflight reimplements the logic that lives in
`tests/windows/adaptive_win32.py:207` rather than importing it. Shipped code
must not depend on a test package.

### Checks that refuse because no source exists

`assert_launch_ready` does not prove legacy writer exclusion. That proof needs
the POLICY scope, and the guardian holds POLICY for the whole launch, so a
wrapper that took it would deadlock against the process it is calling. The
method says so at `host_authority.py:285` and the wrapper host repeats it at
`wrapper_host.py:228`. The guardian asserts exclusion at prepare, at claim and
at bind, so a scope that is not excluded still cannot complete a launch. What
is missing is a wrapper side proof, and it is absent rather than assumed.

`assert_excluded` refuses with `host_exclusion_guardian_unavailable` whenever
the authority was built without a retained guardian process, because there is
then no identity to look for in the infrastructure registry. A PID is not a
substitute and none is accepted.

## What each host does

### Guardian host

`py -m sentinel.adaptive.guardian_host --data-dir ... --journal-dir ...
--guardian-epoch ...`.

`start` at `guardian_host.py:114` runs the capability preflight first, then
builds the store, the `RecoveryJournal`, the `GuardianLaunchOwner` with
`HostAuthority`, the `LaunchService` and `LifecycleQueryService` listeners,
`GuardianControl`, and last the `ControlProposalService` listener described in
`P3-CONTROL-TRANSPORT.md`. `run_once` at `guardian_host.py:237` is one bounded
iteration: serve a pending launch RPC with a bounded timeout, serve a pending
helper proposal, serve a pending query RPC, reconcile lifecycle, then
`control.tick(now)`. The host itself never calls `control.apply`; only the
proposal service does, after it has authenticated the registered helper. It never kills,
suspends or trims anything, and there is no second mode switch beside the
ledger mode, so nothing can disagree with it about whether a native Set is
allowed.

`close` refuses while any execution is still retained. `main` therefore drains
first through `drain_until_settled`, which keeps reconciling without serving
new launches until custody is empty. An interrupt during the drain is reported
as `guardian_host_interrupt_deferred` and the drain goes on. Ending the process
by force is a guardian death, which the supervisor handles.

The default mode runs until the process is interrupted. The repository has no
other stop signal, so `KeyboardInterrupt` is the only stop condition. A positive
`--iterations` is the bounded mode for tests and diagnosis.

An exception out of `control.tick` is not caught in `run_once`. It ends the
process, which the supervisor can recover from. A guardian that stayed alive
while its lease sweep kept failing would hold a cap that nobody is allowed to
restore, because the supervisor restores only after a verified death.

### Supervisor host

`start` at `supervisor_host.py:200` refuses when the supervisor process is
itself inside a Job, mints the guardian epoch through `mint_guardian_epoch` at
`supervisor_host.py:83`, and creates the child with plain `CreateProcessW`
semantics. There is no breakaway flag and no parent spoofing. The creation
handle is kept and the `VerifiedProcess` witness is built from that handle
through `duplicate_from_handle`, never from a reopened PID. See
`sentinel/adaptive/identity.py:361`.

`run_once` at `supervisor_host.py:304` ticks the attached `GuardianSupervisor`
and starts a replacement only after `IdentityStatus.DEAD`. UNKNOWN holds. A
missing PID, a failed OpenProcess, an expired TTL and an abandoned mutex are
never treated as death. A replacement is attempted only after `close()`
succeeds, and only with a new epoch, which `_start_guardian` at
`supervisor_host.py:240` checks before the child is created rather than after.
The supervisor never restarts a workload.

Attach follows the contract of `GuardianSupervisor.attach`. When capture
succeeded and only the first inventory read failed, the supervisor that travels
on the exception is adopted and ticked, and no second attach is made. When
capture itself failed, the partial recovery owner on the exception is closed.
One that refuses to close is kept in `unsettled_captures`, reported by `close`,
and turns the exit code into `EXIT_UNSETTLED`.

`RecoveryOwner.capture` reads `adaptive_runtime.guardian_epoch`, and a guardian
writes it only when it prepares its first execution. On a fresh ledger the
first attach is therefore refused with `recovery_capture_binding_unverified`.
The child already exists at that point, so `start` reports `attached: false`
and the host stays up. Each iteration reports the guardian as `unattached`,
says what the retained witness observes, and retries the attach against the
same guardian and epoch. `max_guardians` defaults to 1, so no replacement is
started unless the operator raises it.

This leaves a window that is not closed. Capture requires a live guardian. If
the guardian prepares its first execution and dies before the next attach
retry, this supervisor can never attach to that epoch, so it cannot restore
through it. The iteration keeps reporting `unattached` with the witness
observing `dead`. Closing the window needs a recovery path that starts from an
already dead guardian. The plan describes one, where the supervisor reopens the
Job from the manifest, and `RecoveryOwner.capture` at
`sentinel/adaptive/recovery_owner.py:93` does not allow it today.

Stopping the supervisor does not stop the guardian. The record says the
guardian was left running, and nothing can adopt it afterwards because the
creation handle cannot outlive the supervisor process. A refusal during `start`
after the child was created reports `guardian_created`, the pid and the epoch,
and returns `EXIT_UNSETTLED` instead of `EXIT_REFUSED`.

### Wrapper host

`py -m sentinel.adaptive.wrapper_host run-managed --command ... --data-dir ...`.

`run` at `wrapper_host.py:260` performs the capability preflight, reads its own
logon SID from its token, takes the three real OS standard handles, loads the
status and config documents, builds the spec, opens the real `Coordinator`,
builds the live `HostAuthority`, binds the guardian endpoint and then drives
`ManagedLauncher` through `admit_once`, `launch_once`, `reconcile_bind`,
`poll_root` and `close_local`. The root exit code is the process exit code.
stdout carries workload output only. Every record this host writes is a JSON
line on stderr.

A refused managed launch never falls back to running the command. Without
`--require-managed` the host reports unmanaged and still does not run it,
because there is no unmanaged launch path to fall back to.

## Endpoint discovery is not delivered

The wrapper is told which guardian to talk to. It takes `--guardian-pid`,
`--guardian-created-filetime`, `--endpoint-instance-id` and `--guardian-epoch`
on the command line, and `_guardian_endpoint` at `wrapper_host.py:207` builds
the pipe identity from those four values. The pipe layer checks the pair
against the server that actually answers, so a wrong pair fails the RPC instead
of quietly connecting to some other process.

No record publishes those values. `adaptive_runtime` carries the guardian epoch
and the active logon, and nothing anywhere stores the guardian pid, its
creation FILETIME or the launch pipe instance id. Production discovery is
therefore not delivered, and no registry was invented for it. Today an operator
passes the values by hand, which makes the wrapper usable for a controlled test
and not usable unattended.

## The data directory is the real ledger

`--data-dir` names the directory holding `sentinel.db` and `status.json`.
Starting the guardian against the daily Sentinel data directory writes the
infrastructure registry into the daily ledger through `_register` at
`guardian_host.py:172`. Nothing in this task did that. Every test and every
smoke run used an isolated temporary directory, and the daily ledger was not
opened for writing.

## Exit codes

| Code | Meaning |
| --- | --- |
| root exit code | the managed run completed and this is the workload's own result |
| 3 `EXIT_REFUSED` | refused with `--require-managed` before any process was created |
| 4 `EXIT_UNMANAGED` | the same refusal without `--require-managed`, and the command was not run |
| 5 `EXIT_POST_LAUNCH` | refused after a create was attempted |

The last one exists so a caller cannot read a post launch refusal as proof that
nothing ran. `_refused` at `wrapper_host.py:486` reports `launch_state` as one
of `not_attempted`, `attempted_unknown` or `launched`, and `command_started` is
`null` for the unknown case rather than `false`. A workload can return these
same small integers, so a caller that needs certainty reads the JSON record on
stderr instead of the exit status.

## Capacity release is a gap

Once `admit_once` is allowed, the reservation is bound to the execution, and
nothing in the repository releases it afterwards. Both call sites that archive
a reservation skip bound allocations first: `Coordinator._cleanup_locked` at
`sentinel/coordinator.py:443` and `Coordinator.release` at
`sentinel/coordinator.py:854`. TTL expiry only marks a hold, through
`hold_expired_allocations` at `sentinel/adaptive/store.py:302` and
`hold_bound_allocation` at `sentinel/adaptive/store.py:322`, whose docstring
states that TTL is health evidence and never a release condition. The ledger
also enforces this with the `managed_allocation_release_requires_terminal`
trigger, which rejects a delete of a reservation behind a non terminal
execution.

So an abandoned wrapper attempt leaves a bound reservation in place until some
path finalizes the execution. That is reported here as a gap. No release was
added, because a closed handle, a refusal and an expired lease are none of them
proof that the process is gone.

## Synthetic material

Every synthetic element lives in the tests, and each is labelled there.

- `SYNTHETIC` in `tests/test_adaptive_host_authority.py:43` is a fabricated
  `HostCapability` used to reach the checks that sit behind the preflight on a
  machine where the preflight refuses.
- The guardian, supervisor and wrapper host tests assign fixture collaborators
  onto a constructed host object. The launcher fixtures come from
  `tests/test_adaptive_launcher.py`, which opens no DLL, pipe, Job, process or
  database.
- `WrapperHost(launcher_factory=...)` is the one production seam added for
  tests. It still receives the live readiness object that the host built, so a
  test cannot substitute a readiness receipt.
- The ledgers in these tests are real isolated SQLite files in temporary
  directories, and the wrapper surface tests run a real managed admission
  through the real `Coordinator`.

There is no measured native timing anywhere in these hosts. The RPC deadline
and the poll interval are configured values, and they are described as such.
No native P3, P4 or P5 gate is claimed.

## What this machine answers

Every host process refuses on this development machine, with
`host_foreign_parent_job` from `read_host_capability`. The process sits inside a
Job it does not own, so it cannot be given an independent CPU rate denominator,
and the preflight refuses rather than approximating one. Each host module has a
subprocess smoke test that starts it against an isolated temporary data
directory and asserts exactly that typed refusal, and that stdout stays empty.

## Follow-ups, not done here

1. A helper host for `FrameSampler` and `ShadowHelper`. There is no helper to
   guardian `ControlProposal` transport in the repository, and none was
   invented.
2. Endpoint publication, so a wrapper can find the guardian without an operator
   typing four values.
3. A finalization path that releases a bound managed reservation after the
   execution is verifiably terminal.
4. Guardian self deregistration. `unregister_dead_infrastructure_locked`
   requires a DEAD identity, and `MAX_INFRASTRUCTURE` is 32, so a guardian that
   exits cleanly leaves its registry entry behind.
5. Supervisor attach against a fresh ledger refuses with
   `recovery_capture_binding_unverified` at
   `sentinel/adaptive/recovery_owner.py:102`, because
   `adaptive_runtime.guardian_epoch` is written only by `register_job_scope` at
   `sentinel/adaptive/store.py:1729` and `mark_prepared` at
   `sentinel/adaptive/store.py:1775`. The host now stays up and retries, as
   described above. A real attach against a ledger with a prepared execution
   was not exercised end to end, and the dead guardian window stays open.
