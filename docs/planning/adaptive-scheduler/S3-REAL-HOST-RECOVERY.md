# S3 real-host recovery evidence producer

This implements the bounded S3 evidence/fixture foundation for the formal
`IMPLEMENTATION-PLAN.md` §§11.2, 11.5 and 12.1. It is **not a measured S3 pass**,
production activation, a complete matrix runner, or permission to change daily
settings. Native fault tests have not been executed for this change.

## Resolve the capability dependency without inventing a pass

The production `NativeEvidenceAuthority(purpose="isolated_canary")` requires
S1, S2, S3 and P4. Using that authority to produce the first S3 result is a
circular dependency. Formal P1 explicitly permits isolated recovery spikes
before promotion. The narrowly scoped test-only `SpikeRecoveryAuthority`
therefore validates the original pinned v1 S1/S2 artifacts, current build,
Windows context, profile and original native wrapper topology. It permits one
existing isolated execution for an original non-renewable 120-second period.
Every later-started fixture host receives that same original case deadline;
creating a helper or guardian later cannot restart the observation clock.

It is named `recovery_spike`; it does not fabricate a previous S3/P4 artifact
or modify the production authority. A fixture directory, status file, bool,
reservation ID, supplied callback or serialized receipt is not continuous
admission. The trusted `adaptive_admission.require_continuous_admission()`
provider must supply the original same-host allocation bridge and verify
`assert_spike_covered(data_directory=..., execution_row=...)`. The current
provider remains default-deny until that integration is implemented.

## Source now present

- `tests/windows/adaptive_recovery_authority.py`: validates strict S1/S2
  artifact bytes and the current native context; binds exactly one actual
  `GuardianLaunchOwner`, its Job, original wrapper/root witnesses and measured
  launch provenance. Helper authority is proposal-only and cannot impersonate
  the guardian actuator. Receipt checks inside held fences do no disk/IPC work.
- `tests/windows/adaptive_recovery_runner.py`: reads actual production ledger
  rows in a read-only transaction and queries a retained native Job. Reduction
  requires fault observation followed by disabled flags while work still lives,
  correct accounting through child survival, complete writer instrumentation,
  no overlapping writes or workload kills and positive final cleanup. Missing
  evidence never becomes a zero. Post-Set faults require a matching actual Set
  attempt/completion, and every fault is bound to the queried execution/nonce.
  An uncertain or unmatched native Set invalidates the measurement even if a
  later restore succeeds. Original actor handles remain retained after
  uncertain close; no raw PID reopening or automatic retry grants authority.
- `tests/fixtures/adaptive_recovery_host.py`: invokes the actual supervisor,
  guardian, operational active helper and managed wrapper. The supervisor keeps
  its genuine CreateProcess/creation witnesses and only changes its test child
  entrypoint to this bootstrap. Test interposition records the real native Set
  boundary and calls the original implementations. The boundary
  hooks cover intent-before, intent-after/Set-before, Set-after/Query-before,
  Query-after/audit-before, lease renewal, guardian hang, root-exit-after,
  wrapper loss and actual SQLite audit-write unavailability. Guardian hang
  still needs externally verified liveness/death/fencing observations before
  its result can qualify.
- `tests/fixtures/adaptive_recovery_workload.py`: one bounded CPU child plus its
  root, each verifying actual Job membership before work. A root-exit trigger
  intentionally leaves its child in the Job. Both use the same original
  cooperative deadline; no fixture kills its workload.

The fixture can deliberately exit only its own verified guardian process.
There is no general terminate-by-PID/name interface. Guardian hang is an actual
wait retaining the real fences; no Suspend/Resume or pretend timeout takeover.
All withdrawal, manifest reconciliation, final accounting and retirement still
run through production modules. Wrapper exceptions stay with production
`settle_release`; the bootstrap cannot convert an uncertain Create into a
normal refusal or retry the command outside admission.

## Integration work still blocking native execution

1. Implement and review the common authenticated cross-process daily allocation
   bridge. It must initialize an isolated test scope and make the same original
   demand floor available to its real supervisor/guardian/helper/wrapper without
   copying status, charging only an expiring reservation, or trusting JSON IDs.
2. Connect the complete case orchestrator to that bridge: start real hosts,
   launch the wrapper from an actually measured S2 PowerShell topology, retain
   original process objects/witnesses, observe bindings, arm the exact boundary,
   request cooperative stop and positively settle every actor.
3. Initial cap setup currently still needs real helper HIGH/baseline samples.
   No fake CPU frame, `_high_streak` mutation or skipped guardian policy check
   is installed. A reviewed isolated native-cap setup operation may separately
   test P1 recovery without claiming P5 policy selection; that operation is not
   yet implemented. Until then, absent real pressure is an honest setup blocker.
4. Complete fault drivers for grant commit/restore, guardian takeover,
   grant-before-cap, recovery-owner race and independent supervisor recovery,
   plus the independent observer side of the hang fixture. Do not silently omit these from the v1
   14-case, ten-iterations-per-case matrix. Existing protocol-only fixtures are
   not accepted as replacement measurements.
5. Finish aggregate native evidence publication. It must validate the full
   production S3 schema, retain raw actor/Job/ledger observations and publish
   nothing as S3 success if any required case or cleanup is unverified.
6. The final runner must prove complete original actor inventory, not merely that
   every actor it happened to register has closed. This limitation is not solved
   by the schema-only aggregate or portable test results.

## Additional driver contract

The additional source injects root-exit-after, wrapper-loss and audit-unavailable
at their real host boundaries. Root-exit-after requires the original retained
root witness to be DEAD while the original Job still contains children, before
faulting only the fixture guardian. Wrapper loss requires the original bound
wrapper's current process witness, live contained work and a native cap, then
faults only that wrapper itself. Audit unavailability holds a real isolated
SQLite `BEGIN IMMEDIATE` writer lock in a retained fixture thread. The unchanged
guardian audit method must return an actual BUSY/LOCKED error; the fixture does
not delete or corrupt the ledger, replace a native Query, or intercept owned
restoration. The fixed fixture
deadline or explicit release signal ends the injected audit outage so cleanup
can continue; reaching that deadline still fails the observation.

Every fault-effect observation must bind the same point, execution and nonce.
Death evidence must identify the actual retained process witness. A root exit,
grant, recovery race or takeover additionally needs its own case-specific
evidence; an unrelated guardian exit is insufficient. A successful first restore
cannot conceal a later re-cap. Matrix accumulation fixes all fourteen cases and
ten distinct iterations each, preserves raw records, rejects mixed runs/reused
scope nonces, and cannot publish an aggregate before every cleanup settles.
`RecoveryMatrix` is this completed-case accounting owner, not a native host
factory: it accepts only its original finished `NativeCaseObserver`, preserves
raw-log hashes and validates the full production S3 schema. It does not launch
140 experiments through an unimplemented provider or claim to be the missing
end-to-end orchestrator. Replacement actors use distinct per-process logs so a
new guardian cannot overwrite the dead original guardian's fault evidence.
Actor-log collection is incrementally bounded to sixteen files, 8,192 total
events and 2 MiB total raw data per case, in addition to the existing per-file
limits. An excessive replacement loop fails evidence collection rather than
growing an unbounded list. Repeated readiness records retain the first actual
installation time for each writer role; replacement startup does not rewrite
the original fault chronology.

The original six control cutpoints now retain the actual proposal and entry
through the production begin/renew call. Intent-before captures the original
validated manifest; intent-after uses the real durable publication ACK and its
pending action. Set-after records the exact completed native write attempt
without inserting a verification Query before the fault. Query-after accepts
only the original decision's APPLIED action, while renewal accepts only its
RENEWED action and captures the previous deadline. Their raw records include
the hash-checked manifest, proposal, action ID, sequence, target and actual
Query/lease timestamps. A RESTORED audit cannot masquerade as either cutpoint.
The reducer requires these records and cross-checks native write chronology;
method-entry labels alone no longer qualify those cases.

The remaining cross-process experiment creation registry and typed native
cleanup capability are explicitly unavailable as
`experiment_scope_binding_unavailable` and `experiment_native_cleanup_unverified`.
Same-row daily experiment admission alone does not unlock either prerequisite.
No callback-driven native runner, synthetic HIGH or serialized "ready" field
substitutes for them. Grant ownership, recovery contender creation and the
independent-supervisor loss experiment stay blocked until their original actor
custody can be authenticated through that bridge.

## Verification boundary

`tests/test_adaptive_recovery_authority.py`,
`tests/test_adaptive_recovery_runner.py` and
`tests/test_adaptive_recovery_faults.py`, plus the later
`tests/test_adaptive_recovery_matrix.py`, are portable boundary tests. They use
explicit synthetic collaborators and do not prove any Windows capability.
The later cutpoint/driver/matrix extension has passed syntax and scoped diff
checks only at this source checkpoint; its central test run is still pending.
On 2026-09-22 the central normal-admission run covered the original 59 tests together
with S1/S2/inventory/P4: **161 tests passed in 41.676 seconds, zero failures,
errors or skips**. An earlier authority fixture run left SQLite connections
open on Windows; explicit close fixed the 27 cleanup errors without changing
assertions or native proof requirements. Protected dirty baseline and adjacent
source integration were present. No clean-clone run or native fault injection
is claimed.
All seven added Python source/test files passed AST parsing; no test pass is
inferred from that syntax check. Static review caught and fixed host-argument
path redirection through equals/abbreviated options, unbound/no-Set recovery
claims and loss of ambiguous fixture cleanup custody.

A real single-fault result must restore within eight seconds including observed
detection delay. Simultaneous owner loss only demonstrates eventual independent
supervisor recovery, still within the original 120-second observation limit.
Expiry stops evidence qualification; it never releases allocation, removes a
cap, closes native ownership or authorizes killing work. Failed cleanup keeps
the original owners alive. Daily runtime remains unchanged and adaptive remains
off until all required measured gates pass.
