# Guardian lifecycle consumer and native ownership

2026-09-20. Continues the implementation from `ff54803`; no daily runtime
deployment, migration or feature activation. The protected incoming worktree
overlay remains outside this change.

## Implemented path

`GuardianLifecycle` consumes an already authenticated and reconciled launch. It
owns the retained Job, wrapper and root process handles independently of the
wrapper, dispatches lifecycle evidence by execution ID, and retains at most ten
executions. It does not recreate a `ManagedAdmission` in another process or call
the wrapper's current-process snapshot after that wrapper dies.

The observer uses actual native Job accounting and membership queries, the exact
retained root's termination signal and exit code, and the formal recovery journal.
Root exit changes the ledger to `DRAINING`; surviving children keep the physical,
Commit, CPU and I/O allocation. The guardian's observed heartbeat updates the
managed row and its unique direct/routed allocation in one transaction. It does
not lower demand, clear a hold, renew an exemption, change `expires_at`, or release
anything. Complete lifecycle lease renewal is not claimed by this heartbeat API.

Only positive empty membership, a sealed launch, currently disabled CPU control
and a settled matching manifest allow the store's existing terminal transaction
to archive/release. POLICY and the per-execution mutex remain held from native
observation through the SQLite commit/rollback. A lost finalization acknowledgement
uses a separate exact terminal/archive proof; missing active allocation alone
is never proof of completion. Cleanup follows verified terminal publication.

Transient adoption failures retain the same owners and can revalidate them without
reopening or replacing handles. Guardian, wrapper and root identities must be
distinct; the guardian must be positively outside this workload Job. A missing
ledger remains missing: the guardian requires a store with sticky existing-only
connections, including the policy coordinator's own transactions.

## Shared native and recovery dependencies

`NativeJob` implements the real named-Job APIs with an explicit protected logon
ACL. Creation rejects name collisions, checks the disabled/zero-limit baseline,
then reduces the temporary creation handle to explicit QUERY, LAUNCH, CONTROL or
OWNER rights. Workload termination rights are not requested by returned handles.
Query-only handles cannot call Set through this API. CPU disable clears ENABLE;
closing any handle neither disables a cap nor establishes process termination.

The existing S1 adapter now consumes this shared implementation while retaining
its opt-in and supported-host preflight. Failed or unknown native cleanup retains
the owner. Failure reporting checks explicit cleanup state rather than requesting
a raw handle whose validity is unknown.

`RecoveryJournal` consumes the production `RecoveryManifest`. Its default Windows
publication uses same-directory staging, file fsync, a write-through namespace
operation and exact readback. Sequence/hash CAS and repeated held-scope/native
Query checks surround publication. Failure is not permission to Set, even if the
new file is visible afterward. No test-only record can deserialize as a formal
manifest. The provisioned directory and ancestors must already have appropriate
access protection; this is not hostile same-user path-race isolation or a claim
of hardware power-loss durability.

`VerifiedProcess.exit_code()` waits for a positive termination observation on the
same retained handle before reading its DWORD. A terminated process returning
259 is handled as that real exit code; the value alone is not a liveness test.

## Minimal contract addition

The formal recovery record previously identified an execution and allocation
floor but did not identify its exact reservation or execution specification.
This change adds required `reservation` and `spec_hash` fields to the not-yet-
deployed production manifest shape. Their validation and hash coverage prevent
recovery from accepting a different allocation under otherwise similar metadata.
Parent subspans cannot own a Job manifest. Older incomplete shapes are rejected;
no daily state or fixture record is silently converted. This is a strengthening
of exact recovery binding, not a second capacity ledger or a policy change.

## Remaining phase gates

This consumer is not the complete guardian service. Authenticated mutation RPC,
wrapper-to-guardian launch transfer, supervisor startup/restore ownership, and
the real loaded-writer/admission cohort integration remain outstanding. The
consumer exposes restoration requirements and does not itself implement the
normal CPU actuator or a restore-only takeover after guardian death.

P3 remains incomplete. P4 still needs bounded per-Job sampling, its shadow loop
and measured overhead. P5/P6 still require supported native canary/recovery and
real-command A/B evidence. Previously recorded foreign-parent-Job and runtime
authority prerequisites are unchanged; this slice does not repeat those probes
or weaken their gates. Adaptive remains off.

## Validation

Windows x64, Python 3.13. Tests ran against exact clean Git-index exports through
the daily `invoke-sentinel.ps1` wrapper: HEAVY, P2, CPU 1, RAM 1 GiB, I/O 0,
without exemptions. Control/launch spikes remained disabled. SQLite and journal
tests used isolated temporary directories; portable native failures use explicit
fixture backends, not observations from the user's workloads.

| Candidate tree | Executed scope | Result |
|---|---|---|
| `06104fb2dd189221b90a79ae71d547e9e732eb87` | Combined source regression suite and two explicit native Job checks | 493 run: 463 passed, 30 setup errors, 0 failures/skips |
| `15af3cae8cc42405f3b89958b385ea67c5bb38d4` | Guardian lifecycle module after correcting the pre-registration fixture shape | 30 run: 27 passed, 1 failure, 2 errors, 0 skips |
| `533ce6f98d31fc231eba8c36fe498c90b32db5c9` | Guardian lifecycle module after correcting reason identifiers and instrumenting actual mutation targets | 30 passed; 0 failures/errors/skips |

The first fixture read `job_name` before registration had populated that optional
column. The second run reached the actual lifecycle paths; its remaining fixture
problems were two non-identifier error reasons and a transaction probe that
incorrectly required the Job/POLICY fences during POLICY's own pre-acquisition
nonce transaction. Production code was unchanged between these candidates.
The probe must instead assert fences on actual lifecycle/allocation mutations
through commit and connection cleanup, without exempting a missing fence.
The final probe uses SQLite's actual mutation authorizer, verifies both positive
targeted writes and rejection of an unfenced lifecycle write, and retains the
same guard through transaction/connection cleanup. Only the guardian test file
differs between the first and final candidates. All production bytes and other
test modules are identical. There was no fresh combined 493-test rerun and the
overlapping runs are not added together.

The initial combined module command was:

```text
py -m unittest tests.test_adaptive_contracts tests.test_adaptive_identity_exit tests.test_adaptive_identity tests.test_adaptive_identity_cleanup tests.test_adaptive_production_recovery_journal tests.test_adaptive_guardian_accounting tests.test_adaptive_guardian_lifecycle tests.test_adaptive_native_job.NativeJobTests tests.test_adaptive_native_job.NativeJobBindingSmoke.native_bindings tests.test_adaptive_native_job.NativeJobBindingSmoke.native_empty_job_smoke tests.test_adaptive_s1_owner_integration tests.test_adaptive_created_identity tests.test_adaptive_native_launcher tests.test_adaptive_execution_owner tests.test_adaptive_control_authority tests.test_adaptive_continuous_admission tests.test_adaptive_lifecycle tests.test_adaptive_evidence_scope tests.test_adaptive_job_scope tests.test_adaptive_finalization_restore tests.test_adaptive_control_slot tests.test_adaptive_policy_scope tests.test_adaptive_managed_admission

py -m unittest tests.test_adaptive_guardian_lifecycle
```

The native DLL layout check and actual empty-Job smoke both passed. The latter
created one randomly named `ResourceSentinel.Test.Job`, verified its ACL,
disabled/zero-limit baseline, empty membership and non-inheritable handles, then
reopened that same continuously held Job with QUERY rights. All its owners
reported successful cleanup. It performed no Set, process launch or assignment.
This proves that limited object/API path on this host, not containment, CPU
enforcement, compatible shell behavior or fault-recovery capability.

After all three runs, all test reservations were released. All 15 staged
source/test files matched the tested export and working copies. The 35 monitored
daily source files and daily config matched the preserved baseline. No workload
Job limit was set, no test Scheduled Task was created, and all empty-Job handles
were positively closed. There is no test CPU restriction to withdraw.

Raw logs, exact test reservation IDs and runtime fingerprints stay in the private
work directory. Documentation-only edits after verification do not change the
tested code. No phase promotion is claimed; full service, native S1/S2/S3,
overhead and A/B gates remain unverified.
