# Control coordination implementation evidence

2026-09-20. This is a source-level P3 dependency and test-host integration,
not completion of native P1 or the P3-P6 release gates. Adaptive remains off.

## Implemented consumers

The public `Exemptions.grant()` and `revoke()` now delegate their actual writes
to `sentinel/adaptive/exemption_sync.py`. The new code atomically enforces three
unrevoked, unexpired grants, retains the original ID/deadline on repeat grants,
and increments a database revision only when lease data changes. No grant is
automatically issued, extended or revoked.

An explicit `bind_policy_locked()` operation binds an isolated exemption ledger
to the same stable POLICY instance/logon as its lifecycle ledger. It installs
persistent SQL fences against older cooperative writers, including connections
opened before binding. A bound public writer uses the existing lifecycle ledger
without creating/migrating it, acquires its actual POLICY guard, and revalidates
the binding. No exemption transaction is held during native mutex acquisition;
transactions in the two databases do not overlap. Missing/corrupt bindings and
uncertain cleanup do not reopen an uncoordinated path.

Binding preserves the exemption store's UUID in a sticky intent in the
lifecycle ledger before enabling coordinated writes. Each transaction finishes
before the next starts. A crash between these steps leaves public mutation and
control unavailable; explicit retry can bind only the original intact store.
For calls starting after binding, losing/replacing the exemption database cannot
recreate an empty unbound grant authority. Malformed revocation values cannot
silently release a grant slot. The cross-file preflight is not atomic protection
against arbitrary concurrent filesystem replacement: a writer already in flight
before first binding is outside that post-binding-call guarantee. Native grant
snapshots still require the matching store/binding; actual loaded-writer handoff
remains a separate, uncompleted promotion prerequisite.

Binding is not automatic on feature-off/import. These cooperative SQL fences
are not authentication against code running as the same user that can alter the
database schema. An unresolved prior POLICY entry is not automatically cleared.

`LifecycleStore` now owns one durable control slot. Begin publishes
`HELD + CONTROLLING` atomically before restrictive intent/Set; duplicate ACK is
not permission for another Set. A positively completed rollback is distinguished
from a lost commit ACK. Restore requires exact Job custody, a current disabled
Query and a settled durable manifest, then publishes
`RESTORED + RECOVERY_HOLD`. Restore acknowledgement does not depend on new
admission, exemption DB availability or member enumeration. The slot cannot be
silently archived while held, malformed or ambiguously bound.

The actual test-only `S1Runtime` wraps its host collaborator with
`S1ControlAuthority`, which consumes fresh exemption records and the real slot
transactions. Raw host success callbacks cannot replace them. A grant inside a
Job protects the whole Job. The native scope reader uses retained exact handles;
legacy float creation timestamps cannot establish an exact FILETIME/logon and
remain UNKNOWN. Current legacy grant creation still produces this conservative
identity form; exact native identity capture for new grants is not delivered by
this slice.

The real S1 capped measurement window now calls `owner.wait_capped()`. It sleeps
outside locks for at most 250 ms between checks, revalidates grants/slot/host/
manifest under the retained scopes, and attempts restore on a new applicable or
unknown grant or failed observation. A failed window is never a successful CPU
measurement. This is a bounded polling consumer, not a production guardian RPC
or a measured worst-case response guarantee; individual native/DB calls add
latency. An unresolved restore ACK keeps owner finalization blocked even when
the OS Query is already disabled and the Job is empty.

## Verification

Windows, Python 3.13, normal live Sentinel P2 admission with 1 CPU unit, 1 GiB
RAM and 0 IO slots. The initial request waited for capacity without changing
its estimates or using an exemption. The final clean staged tree was
`e5c83d0e214975c118bb3926de839323e5a28bae`:
**388 tests passed, 0 failures, 0 errors, 0 skips, 76.927 seconds.**

The private harness exported that exact Git tree and ran these modules with
`SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` through the normal live wrapper:

```powershell
py -m unittest tests.test_adaptive_exemption_sync tests.test_adaptive_control_slot tests.test_adaptive_control_authority tests.test_exemptions tests.test_adaptive_ledger_coverage tests.test_adaptive_execution_owner tests.test_adaptive_s1_owner_integration tests.test_adaptive_managed_admission tests.test_adaptive_admission_context tests.test_adaptive_job_scope tests.test_adaptive_finalization_restore tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch tests.test_adaptive_evidence_scope tests.test_adaptive_accounting tests.test_adaptive_policy_scope tests.test_adaptive_policy_mutex
```

The 97 new cases comprise 28 exemption-sync, 45 slot and 24 authority/scope
tests. They use isolated databases, real SQLite transactions and explicitly
synthetic Job/scope/host observations. Existing selected Windows mutex and
current-process identity tests also passed; they are not native Job capability
proof. No CPU restriction, test Job, Scheduled Task or daily exemption was
created. Both exact normal test reservations were verified absent after exit;
35 monitored daily files and the daily config hash were unchanged. All staged
source/test blobs matched the passing export, and the pre-existing dirty
exemption overlay remained intact.

The first tree `32b06d7167f2cefffd26b967f549cccebb1fceb7` ran 382 tests with
7 assertion failures and 21 cleanup errors. The final changes fixed domain
errors being masked by a generic reader, real fixture SQLite handle leaks and
missing synthetic fresh-frame preconditions for canary admission. Two existing
owner assertions now expect the deliberately earlier pending-recovery guard;
they still require retained allocation. No test was removed, skipped or changed
to permit unsafe release. Independent review also found lost-grant-DB and
malformed-revocation gaps; both were fixed with the regressions described above.
The limited re-review found both original issues resolved, with the filesystem
race boundary above explicitly retained. The slot/owner changes also passed
independent source review after their reported fixes.

These results cannot establish native CPU effect, actual grant ancestry,
Windows Job crash recovery, measured polling latency/overhead or production
readiness. Raw failure logs and private baseline material remain local.

## Remaining contracts and promotion boundary

- A healthy production guardian mutation/recovery RPC and the old CPU/IO/trim
  writer handoff are not implemented by this slice. Bound grants report
  `recorded / restore_pending`; callback dispatch alone is not an OS restore ACK.
- Admission remains blocked after restoration. Clearing RECOVERY_HOLD requires
  the separate accounting reconciliation and five fresh uncapped samples; no
  convenience clear operation is added here.
- The real host cohort authority and native S1/S2/S3 gates remain unavailable.
  The existing native experiment guard remains closed. Missing implementation
  is not reported as a Windows API failure.
- P4 sampling/overhead, P5 full-stack isolated fault recovery and P6 paired A/B
  results have not been established. This source/test slice grants no deployment
  or promotion permission.

The existing dirty metadata/UI/coordinator changes are preserved. Only the two
grant/revoke delegation hunks are staged from the dirty exemption facade; clean
export verification must not rely on the untracked attribution module or other
local overlay. Daily config, Scheduled Tasks and startup entrypoints are outside
this change.

## Side-task research disposition

The separately supplied [resource-admission recommendations](../../work/resource-admission-and-commit-recommendations-20260920.md)
were read in full and copied as that single authorized document, with identical
SHA-256; no other daily source was imported.

Adopt within the existing plan: one execution identity/claim, physical and
Commit as separate resource dimensions, one capacity ledger, frozen active
demand floors, and recovery before release. The new control slot and grant
coordination implement part of those existing requirements. Existing typed
resource demands do not imply that all daily legacy request fields have already
been migrated or deployed.

Defer to separately reviewed work: measured per-execution peak provenance,
historical estimator shadow evaluation, wider classifier/input-size rules and
cross-agent durable result delivery. Submitted estimates are not measured peaks;
none becomes a new prerequisite for the wrapper-only P3-P6 MVP. A notification
or durable outbox cannot by itself establish another agent's resume capability.

Keep the pagefile proposal separate from source implementation. Its numbers are
dated historical measurements, not current capacity; no Windows/pagefile change
or reboot is authorized by adopting the document. Do not introduce a second
capacity authority, virtual Commit oversubscription, an external task daemon,
or the excluded kill/suspend/hard-memory-cap controls.
