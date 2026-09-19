# P1 continuous-admission prerequisite: executable rejection

Date: 2026-09-20. Status: implemented; clean-candidate portable verification passed.
This is a prerequisite guard, not a lifetime-coverage implementation or a P1 pass.

The native runners previously documented the live reservation-floor limitation
but did not enforce it. S1, S2 and S3 setup now reject before native host queries,
Job creation, workload launch or CPU control. Explicit opt-in does not bypass
`continuous_admission_provider_unavailable`. S1/S2 write sanitized blocked
evidence; S3 returns the same explicit setup failure. A failed evidence write
cannot continue into native work.

S2's direct launch-host and console-driver CLI paths also reject, before payload
decoding or starting a timer/process. S3's non-restore actor CLI roles reject
before case loading, native error reporting or dispatch; the guardian also
checks before direct invocation. Restore-only actors remain available. Admission
failure must never prevent compare-and-restore of a restriction from an earlier experiment.

No trusted lifetime provider exists yet. The small guard has no argument,
environment switch, receipt-file decoder, alternative-ledger fallback or public
CLI attestation that enables it. There is no unused fixture-proof implementation.

A future provider must independently acquire and bind the actual host, authority
ledger, exact reservation/execution, immutable spec/resources and held caller
PID/FILETIME/logon identity. It must preserve CPU, physical, Commit and IO demand
floors throughout launch, control, failure, restore, verified Job empty and sealed
launch. Owner/provider loss must retain an uncertain hold for reconciliation.
Root exit, TTL expiry, feature-off, handle closure and a fresh heartbeat cannot
release the floor. A one-time observation or declared deadline is insufficient.
That provider, native fencing/recovery and actual accounting integration need
separate implementation and review. Unknown/foreign Job rejection is another
independent prerequisite and remains unresolved.

Portable verification ran on Windows / Python 3.13.3 through normal P2 admission
(1 CPU unit, 0.5 GiB RAM, 0 IO slots), with native spike opt-in explicitly zero:

```text
py -m unittest tests.test_adaptive_continuous_admission tests.test_adaptive_s1_gate tests.test_adaptive_recovery_timing
```

At 02:22 local, **30 tests passed in 0.096 seconds**, with zero failures, errors
or skips. The candidate was exported from index tree
`2ef1014c9db7f0517fc0b0835ba5b52358964582`, excluding the protected dirty overlay.
Only this evidence document changed after the tested export.

The new nine tests exercise actual entry-point rejection, no env unlock,
evidence-write failures, direct fixture CLI boundaries and restore-only routing.
No native control test ran. Independent review found two direct S3 CLI gaps;
both were fixed and re-reviewed before verification. No production runtime,
Coordinator, Sentinel configuration, exemption, Scheduled Task or controller was
changed. The normal test-admission reservation was released by its wrapper.
Adaptive remains off; native P1 and P3–P6 remain unverified. These test results
do not establish continuous coverage or resolve the unknown inherited Job.
