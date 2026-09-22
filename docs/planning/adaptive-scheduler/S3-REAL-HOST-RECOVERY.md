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
  boundary and calls the original implementations. The six initial boundary
  hooks cover intent-before, intent-after/Set-before, Set-after/Query-before,
  Query-after/audit-before, lease renewal and guardian hang.
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
4. Complete fault drivers for root exit, grant commit/restore, guardian takeover,
   wrapper loss, grant-before-cap, unavailable audit DB, recovery-owner race and
   independent supervisor recovery. Do not silently omit these from the v1
   14-case, ten-iterations-per-case matrix. Existing protocol-only fixtures are
   not accepted as replacement measurements.
5. Finish aggregate native evidence publication. It must validate the full
   production S3 schema, retain raw actor/Job/ledger observations and publish
   nothing as S3 success if any required case or cleanup is unverified.

## Verification boundary

`tests/test_adaptive_recovery_authority.py`,
`tests/test_adaptive_recovery_runner.py` and
`tests/test_adaptive_recovery_faults.py` are portable boundary tests. They use
explicit synthetic collaborators and do not prove any Windows capability.
On 2026-09-22 the central normal-admission run covered these 59 tests together
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
