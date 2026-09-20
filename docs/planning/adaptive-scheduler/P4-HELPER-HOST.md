# Resident shadow helper host

2026-09-21. A P4 implementation slice on branch
`codex/adaptive-scheduler-implementation`. Adaptive stays off. Nothing here is
deployed, no configuration can select canary, limited or enforce, no scheduled
task, hook or script was changed, and this is not a P4, P5 or P6 gate pass.

## What exists now

`sentinel/adaptive/helper_host.py` is a runnable process,
`py -m sentinel.adaptive.helper_host --data-dir <directory>`. It wires the
observation libraries that already existed into one resident loop. It carries no
policy of its own: the profile parser, the frame sampler, the shadow helper, the
machine sampler and the host capability preflight are the production modules.

Startup order, and the refusal at each step:

1. `host_authority.read_host_capability()`. Its refusal reason is passed through
   unchanged, as the guardian host does. Nothing is opened before this.
2. `decision.parse_policy_profile` on the file named by `--profile`. A file that
   cannot be read or validated is `helper_host_profile_unavailable`. Mode off is
   `helper_host_mode_off`. Shadow is the only mode that runs.
3. `LifecycleStore(..., existing_path=True)` on `<data-dir>/sentinel.db`. A
   missing or unreadable ledger is `helper_host_ledger_unavailable`. The host
   never creates a ledger.
4. `VerifiedProcess.current()`, then the frame sampler and the shadow helper,
   then registration.

The in-process shadow flag that `ShadowHelper.__init__` accepts is never passed
by this host. The profile file is the only way to reach shadow mode, and
`decision.validate_policy_profile` already refuses enforce from a configuration
file, so enforce has no path here at all. A test asserts that no call in this
source has a `shadow` keyword.

Zero Set is structural. The module imports nothing that can mutate a Job,
publish a recovery intent, reach a guardian or build a proposal, and its source
contains none of the names that would perform or request a control. Both
properties are asserted by parsing the file, so a future import or call fails the
tests rather than passing review.

### The two adapters

`JobHandleSource` is the per-Job accounting backend. It holds `NativeJob`
handles opened with `JobAccess.QUERY` only, keyed by execution id, and one
`read` is exactly one `accounting()` call on a handle the enrollment step
already opened. It never opens, scans or enumerates for the sampler, which is
what the sampler's backend contract requires. A failed query raises
`JobSamplingError` with a sanitized `FrameError`, and an unknown value is never
returned as a zero. Per-Job memory stays `None`, because no private working set
or private commit query for a Job exists in this repository.

`counter_epoch` identifies the retained handle rather than the Job name. While
the handle is held the kernel keeps that exact Job object alive, so its
cumulative user and kernel times stay relatable across reads. A release followed
by a reopen of the same name mints a new epoch, so the sampler drops the delta
instead of bridging two readings that may not belong together.

`membership_complete` comes from one limit query at enrollment.
`JOB_OBJECT_LIMIT_BREAKAWAY_OK` or `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` means
a process can leave the Job, so the Job's own accounting cannot prove that it
covers the whole execution. A limit query that fails leaves membership unproven
as well. Both cases report incomplete membership, which the sampler turns into
`membership_unknown` and a `None` process count.

`MachineObservationSource` copies one `machine_sampler.MachineSample` into the
`sampler.MachineObservation` the frame sampler consumes. The field names already
match, so it is a field copy and nothing more. A `MachineSamplingError` becomes
an observation with no machine, unknown validity, the sanitized error and
`reset_required`.

### The clock, and which tick it is

`machine_sampler._WindowsBackend.tick` reads `QueryInterruptTimePrecise`. The
binding is at `sentinel/adaptive/machine_sampler.py:136`, the method is
`tick` at `sentinel/adaptive/machine_sampler.py:143` and the call it makes is at
`sentinel/adaptive/machine_sampler.py:145`. The module docstring states
the same domain at `sentinel/adaptive/machine_sampler.py:8`: every timestamp it
publishes is in the 100 ns interrupt time domain.

The host builds one `_WindowsBackend`, uses `backend.tick` as the clock for both
`FrameSampler` and `ShadowHelper`, and gives the same backend to
`MachineSampler`. The tick the helper reads and the window endpoints the machine
sampler publishes therefore come from one counter, which is the condition under
which the frame skew check in `FrameSampler.sample` means anything. A caller
that supplies one of the pair and not the other is refused with
`helper_host_clock_domain_unshared`, because a mixed pair would compare two
clocks and call the difference skew.

### Enrollment

Enrollment reads the ledger through `store._ipc_read_transaction`, the same
bounded read-only snapshot the other private readers use: a read-only URI,
`query_only`, a progress handler deadline and a required `adaptive_runtime`
schema and protocol version. The snapshot is released before any Job handle is
opened or closed, so no transaction is held across a native call.

A row is a candidate only when its state is in `legacy_writer._ACTIVE`, its
coverage is `job_contained`, its logon is this process's logon, and its
`job_name` is exactly `Local\ResourceSentinel.Job.{execution_id}.{nonce}` for a
canonical execution id and a 32 hex character nonce. The rest of the row is
bounded in SQL before it becomes a Python value. A row that fails any of these
checks is counted as rejected and skipped; it does not stop the refresh. The
order is by execution id, the count is capped at
`min(profile.max_enrolled_jobs, MAX_ENROLLED_JOBS)`, and what the cap left out
is reported as `left_out`.

`capability_verified` is always False. `read_host_capability` produces a record
that is deliberately never persisted as a readiness flag, so no ledger fact
proves the capability for an execution, and claiming it here would invent one.
`foreground` is always False for the same reason: the ledger carries no
foreground fact.

An execution that has left the live set, or whose Job can no longer be read, is
released: the shadow helper drops it and the handle is closed. The refresh runs
on a cadence, every `--enroll-every` ticks, five by default. A ledger read that
fails releases nothing, because a ledger that cannot be read says nothing about
which executions ended.

### One iteration

One iteration is an optional enrollment refresh, exactly one
`ShadowHelper.tick()`, the release of any Job that just became unreadable, and
then a wait to the next `sample_interval_ms` boundary through an injected sleep.
A late iteration advances the boundary past the intervals it missed and counts
them; it never runs them. The shadow helper already counts its own missed ticks.

A compact record is written every `--report-every` ticks. It contains counts,
the mode, the last stable reason and the loop's own cost. It carries no
execution command text, no path, no Job name, no execution id and no PID of any
workload. Nothing is persisted to the database other than the registry row.

The interval that paces this loop is a timer. It is not a measured reaction
time, and neither is any number in the metrics record.

### Shutdown

`KeyboardInterrupt` ends the loop, every Job handle is closed and the process
exits 0. An unexpected exception out of a tick is reported with a stable reason
and exits 5, and the handles are closed on that path too. Closing happens in a
`finally`, so no exit path leaves a handle open. A close whose outcome is unknown
is reported as `helper_host_handle_cleanup_unverified`, and that handle stays
retained rather than being forgotten.

## Registration, and the restart gap the repo owner should decide on

Registration is the guardian's: `initialize_registry_locked` and
`register_infrastructure_locked`, under one `POLICY` hold, with the same identity
rules. The one addition is a refusal. Before it inserts, the host reads the
helper rows for its logon and refuses with `helper_host_registry_occupied` if any
of them is not this exact process identity.

That refusal is deliberate. `control_transport.registered_helper` refuses a logon
whose registry holds more than one helper row, so a second row would leave the
transport unable to identify a helper at all. Refusing to start is the safe half
of that pair.

The refusal is raised after the `POLICY` scope has ended normally. Review of the
first version found that it raised inside `policy.hold`. An exception that leaves
the hold keeps the durable entry nonce (`sentinel/adaptive/policy.py:250`), and
`prepare` answers a leftover nonce with `policy_scope_busy` for every later
caller (`sentinel/adaptive/policy.py:151`). A stale helper row is the expected
state on a restart, so each refused restart would have blocked the guardian's
next `POLICY` entry with nothing to clear it. The host now counts the other rows
inside the hold, skips the insert, lets the scope exit, and then refuses. A test
asserts that the nonce is gone and that a guardian can register afterwards.

Failures inside `initialize_registry_locked` or `register_infrastructure_locked`
still leave the nonce. That is the same shape recorded for the guardian start
path in `P3-PROCESS-HOSTS.md`, and it is not changed here.

The consequence is a restart gap, and it is not fixed here. There is no live
deregistration function in this repository. A row can only be removed by
`unregister_dead_infrastructure_locked`, which requires a retained handle that
observed `IdentityStatus.DEAD` for that exact identity. A process starting now
cannot obtain such a handle for a process that already exited, and an unknown
status, a missing PID or a failed `OpenProcess` is never death. So the row this
host writes stays after a clean exit, and the next helper start for the same
logon refuses until something removes it.

**This needs the repo owner's decision.** The options visible from here are a
supervisor that holds the retained handle across the helper's lifetime and can
therefore prove the death, or an explicit operator step. Adding a column, a
table, a heartbeat or a TTL sweep would put a removal rule where an authority
record belongs, so this slice did not add one.

## What is not delivered

There is no endpoint, no client and no connection to a guardian. This host never
builds a `ControlProposal` and never sends one, so nothing it observes can reach
the guardian's actuator even if a guardian were running.

There is no supervisor for this process: nothing starts it, restarts it, or
notices that it exited. There is no scheduled task, no hook and no script that
runs it, and none was changed.

There is no per-Job memory attribution, so the memory fields stay unknown and the
decision layer sees them as unknown.

There is no deregistration, as described above.

There is no way to select enforce. There is no kill, suspend, trim, priority
change or rate limit anywhere in this module, and no RAM hard cap.

`--data-dir` is honored exactly as given, and registration writes to whatever
ledger it names. Nothing in this slice was run against the daily data directory.

## What is unverified

Nothing native ran on this machine. The host capability preflight refuses here
with `host_foreign_parent_job`, because this development host runs its processes
inside a parent Job. Every claim above that involves a real Job handle, a real
accounting query, a real interrupt time tick or a real registry on a live system
is therefore unverified by execution. The tests are portable evidence about the
host's wiring, its refusals and its arithmetic.

Specifically unverified:

- that `QueryInterruptTimePrecise` and the Job accounting counters behave as the
  sampler assumes on a supported host;
- the cost of one tick, which the plan states in milliseconds. Every duration in
  the tests comes from a synthetic clock that charges a fixed cost per read, so
  none of them measures anything;
- that a Job with no breakaway limit flag does in fact contain every process of
  its execution for the whole run. The flags prove only what the Job permits;
- that the enrollment cadence and the pacing hold under real scheduling delay.

One import fact worth recording. `helper_host.py` imports `store` for
`LifecycleStore`, `LifecycleError` and `_ipc_read_transaction`, and `store`
imports `writers` at `sentinel/adaptive/store.py:33` for its migration fence.
`writers` is on the list of modules this host must not reach, so the structural
test asserts the exact set of imports this file itself declares rather than a
full transitive closure. `guardian_host.py` has the same edge through the same
import. The host calls nothing in `writers`, and no name from it is reachable
through anything this file imports by name.

## Tests and their labels

`tests/test_adaptive_helper_host.py`. Every Job handle, accounting reading,
machine sample, clock tick and sleep is an explicit in-process fixture, labelled
as synthetic where it is defined. A sleep is recorded and never taken, so the
pacing assertions describe arithmetic and not elapsed time. The synthetic Job
exposes no Set, terminate or rate operation of any kind, so a host that tried to
control a Job would fail those tests rather than pass them.

The ledger, the policy coordinator, the legacy writer registry and the bounded
read-only snapshot are the production modules against a real isolated SQLite file
in a temporary directory. The registered processes are real `VerifiedProcess`
objects over a synthetic handle backend, the same construction the guardian
lifecycle fixture uses. The `managed_executions` rows are fixture inserts; no
launch happens and no Windows Job exists.

The capability preflight is live. The startup case expects this machine's real
refusal and the subprocess case expects a refusal from a separate interpreter.
Where a test needs to get past the preflight it patches the module's own
`read_host_capability` with the synthetic record and says so at the site. That
patch proves nothing about this or any other host.

Covered: the capability refusal before the ledger is opened, an unknown
capability, the off profile, an unreadable profile, a missing ledger, a partially
injected clock pair, registration writing exactly one helper row, a repeated
registration adding none, a foreign helper row refusing the start with no second
row written, that refusal releasing the `POLICY` entry nonce, a guardian row not blocking a helper, the accounting adapter
including its failure and out of range paths, per-handle counter epochs, release
and the unknown close outcome, the breakaway flags and the failed limit query,
the machine field copy and its error path, the enrollment filter, order, cap,
left out count and rejected rows, the release of an execution that left the live
set, a ledger read failure releasing nothing, one iteration ticking exactly once
and pacing with the injected sleep, a late iteration running once, the refresh
cadence, the release of an unreadable Job by the loop, the metrics record
carrying no command text, path or identifier, the interrupt and failure exits
closing every handle, and the two structural properties.
