# Daily accounting handoff: prepared, not activated

This contract concerns the real host's admission provider. It does not authorize
installation, runtime migration, configuration changes, Scheduled Task changes,
or adaptive promotion. The daily checkout still uses the older grace-based
Coordinator. A successful isolated test cannot change that fact.

## Why a longer reservation does not fix S1

The old Coordinator stops adding a direct reservation's CPU and RAM after
`created_at + reservation_grace_sec`; heartbeat changes expiry, not that age.
The default is 120 seconds. Setup, ten measurement rounds, delayed scheduling,
restore, Job-empty observation and cleanup can exceed it. P2's managed demand
floor in the implementation branch survives age, TTL and root exit, but only
consumers running the new projection use it. SQLite DML triggers cannot intercept
an old consumer's read-only reuse of an existing reservation. A matching source
hash or database schema is not evidence of what an already loaded process runs.

The original daily ledger remains the only local capacity authority. An isolated
directory may contain native-test journals and results; it cannot become a
second local admission ledger. Neither repeated admission, moving timestamps,
larger grace, a fabricated lease nor a new exemption solves this handoff.

## Retained handoff owner

The operation is held by one original native process, which will remain the
supervisor's in-process authority. It is never reconstructed from a JSON report.

1. Prepare a private exact manifest of the reviewed candidate and daily source,
   daily configuration, canonical daily ledger, and file identities. Keep full
   paths and source differences local. The public report contains counts,
   digests and stable refusal codes only. Recheck every target before changing
   it; a dirty baseline mismatch stops installation rather than overwriting it.
2. After separately authorized source installation, verify the entire reviewed
   source closure at the actual daily paths. Capture a complete, bounded native
   cohort, retaining original query/synchronize handles. Potential Python or
   PowerShell consumers whose loaded imports cannot be established are reported
   as ambiguous, not as confirmed Sentinel writers. No unrelated process is
   killed or automatically restarted. Missing metadata, incomplete inventory,
   unknown identity and process churn block the handoff.
3. Every old relevant or ambiguous cohort member must be positively DEAD on its
   original retained witness. Only the exact verified current activation owner
   may be excluded. Source replacement, PID disappearance, a new PID lookup,
   elapsed grace and an empty registration table are insufficient.
4. Under the existing POLICY fence and a short SQLite transaction, require empty
   legacy direct/routed allocations and queue, no surviving managed lifecycle,
   and adaptive mode off. Install the additive daily generation and permanent
   compatibility triggers in the real ledger. The generation stores the source
   digest and exact retained owner identity. It is descriptive data, not a
   capability to adopt the owner or an existing Job.
5. All new capacity connections validate actual import provenance against that
   generation before beginning their transaction. `sentinel/__init__.py` must
   enter the stdlib-only `sentinel_daily_bootstrap.observe_package_import()`
   before importing other Sentinel modules. The original CPython audit observer
   retains complete executed module code, including global initialization and
   decorator calls. Already loaded, unobserved or partially initialized modules
   cannot be certified by comparing the file now on disk or by unwrapping a
   function. This cooperative version check is not a security sandbox. A per-connection SQLite
   function then binds writes to that generation. An old connection or old
   consumer lacks it and fails closed. Old read-only reservation reuse has no
   surviving legacy row to reuse at the cutover.
6. The retained supervisor owner continues to validate source, pinned fixed
   policy configuration, ledger and native identity. It checks only original
   old-cohort witnesses after cutover; freshly launched consumers are covered by
   their own import-generation checks. A native caller authenticates that original owner through the
   normal host transport. A serialized manifest or caller-provided boolean is
   never sufficient to construct `S1Runtime` or certify an experiment.

There is no independent new resident daemon. The existing supervisor must retain
this owner, or receive the original native handles through authenticated transfer
while the sender retains them until acknowledgement. The operator cannot finish
an activation CLI, discard its witnesses, and reopen by PID later.

## Exact integration boundaries

`prepare_connection(conn, role, db_path)` belongs before `BEGIN`, not inside a
capacity transaction. It checks the current generation and loaded code and
registers the connection's generation function. It performs no schema migration
or allocation. Its roles are `coordinator`, `maintainer`, `lifecycle`, and
`legacy_writer`; restoration keeps its existing native-first recovery path.

A persisted `ACTIVE` row plus a live PID does not acknowledge installation.
Capacity connection setup requires `DailyReadinessClient.assert_ready` against
the original owner's preminted authenticated endpoint, or the exact retained
owner object in that same process. The native client returns only after peer,
reply binding and channel cleanup succeed. There is no serializable success
receipt or caller-provided readiness callback. A missing service remains a
concrete blocker. Until installation is acknowledged, only the original owner's
in-process lifecycle connection may clear its original POLICY nonce; SQLite's
authorizer denies every capacity, schema and barrier write on that connection.
Later ordinary POLICY operations may legitimately have their own nonce present;
that does not invalidate the already acknowledged installation.

The original owner calls `prepare_install(policy=..., guard=...)` while holding
the exact existing POLICY, before opening its SQLite transaction. `install_locked`
consumes that one-shot preparation and retains installation custody before the
first possible SQL mutation. After commit and POLICY cleanup, the owner closes
the original connection through `settle_install_connection()`; an unknown close
is quarantined. Only separate readback may `acknowledge_install(conn=...)`.
Acknowledgement never infers cleanup from `conn.in_transaction == False`.

Required consumer paths include:

- `Coordinator` admission, reservation retry, release, cleanup and queue paths;
  the `sentinelctl` CLI and Bash/Stop hooks reach this implementation.
- `Maintainer` direct/local-worker routing, heartbeat, cleanup and release;
  `maintainerctl` and `Orchestrator` reach this implementation.
- `LifecycleStore` launch, heartbeat, finalization and recovery accounting.
- The collector's legacy mutation executor for priority, I/O, trim and restore;
  no PowerShell mutation may occur after a permission-only response.
- Wrapper startup and any change-tracker self/child priority setters. The two
  incoming change-tracker setters must be reconciled before activation; they
  cannot silently remain an exception to the writer inventory.
- Exemption integration must retain its existing POLICY synchronization and
  max-three semantics. No generation migration grants or revokes exemptions.

The guarded source closure includes the root import bootstrap, every Python module under `sentinel/`, all
known Python and PowerShell entrypoints under `scripts/` and `hooks/`, and the
canonical shared policy. Missing known entrypoints, extra unreviewed executable
entrypoints or source drift invalidate the prepared manifest.

## Rollback and evidence

The package has no automatic daily apply. Its default commands inspect and
create local evidence only. The separate installation command names the exact
reviewed manifest digest and requires an explicit activation action. Preparing,
testing, or committing this code does not authorize running that command.

Current preparation commands, using the base interpreter and implementation
checkout, are:

```powershell
C:\Python313\python.exe scripts/adaptive-prerequisites.py inspect --private-preparation .local-adaptive/daily-activation-preparation.json
C:\Python313\python.exe scripts/adaptive-prerequisites.py check-baseline --private-preparation .local-adaptive/daily-activation-preparation.json
```

The output file must not already exist. `inspect` exits 3 because its read-only
report cannot establish retained native authority. `check-baseline` exits 0 only
for unchanged protected bytes with no additional unreviewed executable source;
that result grants no activation. Configuration and preparation reads are bounded
to 1 MiB. Private artifacts stay local and are not staged.

After the source integration is complete, generate a fresh preparation: a prior
manifest will not match later source edits. Review the public digest and keep
the private preparation and backups outside the repository. The executable
review path performs no source or runtime mutation:

```powershell
C:\Python313\python.exe scripts/adaptive-activate.py --private-preparation <private-preparation.json> --preparation-sha256 <exact-private-file-sha256> --manifest-sha256 <exact-reviewed-source-sha256>
```

Only a separately authorized operator invocation may apply:

```powershell
C:\Python313\python.exe scripts/adaptive-activate.py --private-preparation <private-preparation.json> --preparation-sha256 <exact-private-file-sha256> --manifest-sha256 <exact-reviewed-source-sha256> --backup-directory <new-private-backup-directory> --apply-daily-accounting-handoff
```

This executable starts with standard-library imports only. It rejects a process
that already imported Sentinel, validates canonical paths and exact source,
configuration and ledger-file bindings, retains original Windows file handles
denying concurrent writes/deletion, and captures exact backups before writing.
The source closure includes unchanged files so another editor cannot change an
already checked module while the operation holds its handles. Existing dirty
bytes must match the reviewed private baseline. A new file uses `CREATE_NEW`.
Parent creation must retain and verify each ancestor; no path-based recursive
copy, delete, checkout, source reset, or broad rollback is performed.

Source writes are in-place and are not a multi-file transaction. A write,
flush, readback or close with unknown outcome retains its original owner and
private operation evidence. The source stage cannot claim successful rollback
from a closed handle or elapsed time. Known unchanged, pre-mutation refusals may
release their handles and exit. Rollback through the retained source objects is
limited to exact files written by that operation before runtime import; it
never restores a pre-activation database. A created directory is not recursively
removed, and deletion-pending for an owned new file is not reported as absence.

After positive source settlement the same interpreter imports canonical daily
Sentinel, captures its original native cohort and becomes `DailyActivationHost`.
It explicitly migrates the real daily ledger, performs the fenced generation
installation and acknowledgement, then owns the existing off-mode supervisor
and one read-only readiness thread. The thread owns a separate, one-resource
native pipe registry; it adds no accounting database or resident process.
Actual native source-file locking, permissions, timing, cohort handoff and
failure recovery still need their Windows evidence before this entrypoint can
be promoted. The command has not been executed against daily state.

The old cohort is first captured after source settlement, then refreshed under
the original POLICY immediately before generation installation. This includes
interpreters started during source replacement. Their exact original witnesses
must be positively dead. Empty legacy allocations are checked under the same
SQLite writer lock that installs generation triggers. A connection opened before
the generation cannot write afterward without the generation function; no old
reservation remains for a read-only reuse path. Reviewed native legacy setters
hold the same POLICY through their exclusion checks and mutations. A renamed,
embedded or otherwise unclassified relevant consumer remains an inventory gap;
this argument does not certify such a consumer merely from its filename.

Rollback first sets desired mode off and follows the operational drain/restore
contract. Live allocations, unknown cleanup, outstanding caps or a retained
compatibility obligation prohibit restoring an old database or old writer.
Once all managed and generation obligations have positive terminal evidence,
restore only exact known source bytes. Preserve the upgraded ledger as evidence;
do not overwrite it with a pre-activation backup that could erase newer work.

Native S1/P4/P5/P6 runners must retain the genuine provider throughout their exact
workload, restoration, positive Job empty, ledger finalization and handle cleanup.
A generic callback saying cleanup succeeded cannot release capacity. Aggregate
P4 fixtures and A/B managed wrappers need exact adoption or a single declared
envelope; they cannot double reserve, swap to a test ledger, or release at root
exit. Preparing this handoff does not itself finish those runner integrations.

This document is a frozen implementation contract, not native handoff evidence.
The source provider must remain unavailable until the live cohort, daily
activation and exact runner custody integrations are actually present.

Prepared module APIs and remaining integration are deliberately distinct:

- `SourceManifest` and the CLI create/revalidate review evidence; they never
  authorize a native experiment.
- `RetainedCohort` retains actual old process witnesses. Its filename discovery
  marks interpreters ambiguous; embedded/renamed consumers and missing trusted
  entrypoint inventory remain blockers, not claims of complete coverage.
- `DailyGenerationOwner` provides the exact fenced migration/acknowledgement
  primitives and retains source/config/ledger identity and original custody.
- `DailyReadinessService` provides authenticated readiness of that exact owner;
  it neither allocates resources nor adopts a command or external test Job.
- The canonical package bootstrap and Coordinator, Maintainer, LifecycleStore
  and legacy-writer connection hooks call the generation check before BEGIN.
  With no installed generation, ordinary legacy behavior is preserved.
- `DailyActivationHost` assembles the original owner, migration, readiness thread
  and existing supervisor. Genuine S1 provider construction, S1 canonical
  naming/history reconciliation, and multi-process experiment adoption remain
  separate integration obligations. A global source readiness response cannot
  stand in for `assert_spike_covered`.

An activated generation retains a live owner dependency. Missing readiness
refuses new capacity; stopping the owner or turning adaptive off does not remove
the compatibility fence. Availability and monitoring cost must be measured in
the required gates. No ordinary user work may be killed to satisfy the cohort.

Generation retirement has a separate original-owner source path described in
[DAILY-GENERATION-RETIREMENT.md](DAILY-GENERATION-RETIREMENT.md). Ordinary Ctrl+C
drains CPU control and leaves the accounting keeper resident with
`daily_generation_retirement_required`. Explicit `host.request_retirement()` on
that original host, or the separately authorized activation command's
`--retire-generation-after-drain`, records a different intention: freeze new
admission, retain cleanup authority, complete the existing off/drain operation,
verify the full historical custody inventory, seal the generation, then close
the original readiness/cohort/process owners. The flag requests immediate
retirement after successful activation; it does not connect to or adopt an
already running keeper. A row, timeout or caller-provided receipt cannot make
the host exit.

The durable `SEALED` row establishes ledger settlement; only the original
operation reaches in-process retirement after its own final native cleanup.
**Daily admission remains fenced after clean exit.** This is not restored
admission-only service. Fresh-generation restart from positive retirement is a
separate implementation gap, so this activation command is not reusable after
retirement. Every current experiment-demand row blocks retirement until its
native release receipt is implemented. Native activation and retirement remain
unverified and have not been executed against daily state. Daily adaptive mode
stays off.

Python's official [audit-event table](https://docs.python.org/3/library/audit_events.html)
documents the `exec` event's code-object argument.
[`sys.addaudithook`](https://docs.python.org/3/library/sys.html#sys.addaudithook)
describes installation behavior and its security limitations. The implementation
checks an original in-process probe event after installation; suppressed hook
installation cannot silently confer provenance. These APIs do not attest native
cohort retirement, authority transfer, effective CPU caps or runtime activation.
