# Retained admission coverage used by the S1 execution owner

Date: 2026-09-20. Base commit: `d7326c24a944afd881bf2e1ca7989e7c58c4bfd3`.
This completes the direct-ledger assertion consumed by the
[S1 execution owner](P1-S1-EXECUTION-OWNER.md). It is source integration within
P1/P2 support, not a native gate or P3-P6 completion claim.

## What changed

The S1 owner previously delegated all coverage checks to its runtime authority
collaborator. It now always verifies actual ledger custody first, in its
constructor, preparation, lifecycle evidence scope and control entry. A host
callback returning success cannot mask a missing or changed allocation.

- `ManagedAdmission.snapshot_for_ledger()` revalidates the retained exact
  current-process identity and previously submitted canonical ledger path. It
  remains usable after launch is sealed for cancellation/recovery, without
  resubmitting, renewing, unsealing or exporting a claim token.
- `LifecycleStore.assert_admission_covered()` opens one bounded read-only
  transaction against that same absolute path. It checks expected scope/state/
  revision, immutable admission and claim/IPC binding, the unique direct
  allocation, original request metadata and all retained demand floors.
- HOLD and START_UNKNOWN remain verifiable custody states. The assertion never
  interprets a replay's `allowed=False` as proof that the obligation vanished.
  Queued, terminal, missing, mismatched or duplicated allocation fails closed.
- A missing database is not recreated or migrated. Identity is checked before
  the read transaction. The reader has a 250 ms deadline, closes its connection
  before returning, performs no allocation/TTL/claim writes, and returns
  sanitized failures. Restore has no new admission check.

The read supplies a consistent ledger snapshot; the caller must retain its
separate mutation fences. It does not assert that all loaded host consumers use
this ledger, that collector CPU/IO/trim writers have handed off ownership, or
that exemption/control authorization is complete. Direct admission is the
explicit scope of this assertion; it does not silently adopt routed/parent work.

Independent review found a double-resolution race for relative database paths.
The final implementation fixes the canonical absolute path once and passes the
same object to admission validation and the reader. Its regression actually
changes cwd between those operations to a directory containing another ledger,
then proves the original ledger is still read. This is not a claim of protection
against hostile replacement of a database file at the trusted path.

## Verification

Windows 11 build 26340, x64 Python 3.13.3. Normal live Sentinel P2 admission with
1 CPU unit, 1 GiB RAM and 0 IO slots. The wrapper briefly waited for fresh
measurements, then admitted the same request without changed estimates or an
exemption. All test databases were isolated; native spike opt-in stayed zero.

Clean index export `eefe14c02e9bd063cf93799dca30d4b69d4eda8e`:
**237 tests passed, 0 failures, 0 errors, 0 skips, 20.703 seconds.**

```powershell
py -m unittest tests.test_adaptive_ledger_coverage tests.test_adaptive_execution_owner tests.test_adaptive_s1_owner_integration tests.test_adaptive_managed_admission tests.test_adaptive_admission_context tests.test_adaptive_job_scope tests.test_adaptive_finalization_restore tests.test_adaptive_lifecycle tests.test_adaptive_prelaunch tests.test_adaptive_evidence_scope tests.test_adaptive_accounting
```

The 24 new cases use real isolated SQLite ledgers with explicit synthetic self
identity. They cover wrong/canonical DB, unknown/closed context, queued intent,
sealed cancellation, exact row/scope/revision and binding, deficient/increased
floor, retained expired/uncertain work, missing/duplicate allocations, read-only
single-snapshot behavior and the cwd race. Two actual S1 owner regressions prove
an always-successful host callback cannot hide a missing allocation before
creation or changed binding before control authorization/Set. Existing owner
tests exercise this assertion through preparation, launch failure, restore and
finalization with synthetic native operations.

The prior S1 owner suite passed 481 tests before this slice; this targeted run
verifies the new method and all changed owner call sites without presenting
repeated tests as new native evidence. Independent source review completed with
no remaining finding after the path fix. No native Job, CPU restriction,
Scheduled Task, exemption or daily runtime activation was used. The normal test
reservation was verified absent, daily source/config hashes were unchanged, and
the committed source/test blobs matched the passing export.

Native P1 S1/S2/S3 and full P3-P6 remain incomplete. The actual host cohort,
exemption/control-slot/barrier coordination and legacy control-writer exclusion
still require implementation and safe runtime verification. The unavailable
native authority guard remains closed; an isolated data directory does not
provide authority over the daily host. Adaptive remains off.
