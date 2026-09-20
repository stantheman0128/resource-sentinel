# Guardian lifecycle lease renewal

2026-09-20. P3 source integration following the authenticated launch path.
This does not enable adaptive control or complete the P3 native recovery gate.

## Contract implemented

The two existing capacity tables now capture `lease_duration_sec` only when a
fresh direct or routed allocation is created. It comes from that admission's
validated configured TTL, not subtraction of mutable timestamps. Additive
migration leaves older rows NULL. SQL guards preserve the original value,
including NULL, across updates and replacement attempts.

Under retained guardian evidence, POLICY and the same Job fence, one transaction
updates lifecycle and allocation heartbeats. A still-unexpired RUNNING/DRAINING
allocation without a hold reason renews to `max(old expiry, now + fixed period)`.
Repeated renewal cannot increase the period. The reservation identity, resource
floor, root/child custody and user exemption deadlines are unchanged.

An expired allocation keeps its old deadline and atomically records
UNCERTAIN_HOLD (START_UNKNOWN for an in-flight launch). Existing holds are never
cleared by a heartbeat. NULL duration remains observation-only. Expiry and zero
observed members do not themselves release the reservation.

Legacy `Maintainer.heartbeat(task_id)` now refuses lifecycle-bound routed work.
It also refuses a matching malformed registry backreference even if allocation
tags were lost. Valid direct/routed reservation-ID namespaces remain separate.
The actual guardian path is required to renew managed work.

## Validation

Windows; normal daily Sentinel admission, HEAVY/P2, CPU 1, RAM 1 GiB, I/O 0,
no exemption. Tests used isolated databases from exact staged-tree exports.
The protected incoming Coordinator changes were excluded using a verified
task-only patch; other incoming source, policy and dashboard changes remain out
of the commits. No daily schema/config/task/startup deployment occurred.

Tree `fbe5e3755ee24117c84d0aa93e61069a3fac0bdf`: 321 tests, 320 pass, one failure,
zero errors/skips, 44.852 s. The sole failure was the old guardian launch test
asserting that a healthy surviving child's expiry never changes. Updated that
assertion to require the actual 10-second renewal while retaining exact
reservation, period and resource-floor equality and no release before Job empty.

Tree `6fc62ec2963a021845b60acec583376609b5ba2f` differs only in that test:
22 affected launch tests passed, zero failures/errors/skips, 14.235 s. Thus all
321 selected cases have passing evidence across the two runs; no second full
321-case run is claimed. The new lease module contributes 17 isolated tests.

Equivalent commands executed inside each clean export:

```powershell
py -m unittest tests.test_adaptive_lease_renewal tests.test_adaptive_guardian_accounting tests.test_adaptive_guardian_lifecycle tests.test_adaptive_guardian_launch tests.test_adaptive_launch_store tests.test_adaptive_managed_admission tests.test_adaptive_lifecycle tests.test_adaptive_accounting tests.test_adaptive_coordinator tests.test_coordinator tests.test_maintainer tests.test_adaptive_policy_scope tests.test_adaptive_writer_fence
py -m unittest tests.test_adaptive_guardian_launch
```

Both admission reservations were released after the tests. All 35 checked daily
source files and the daily config matched their saved baseline. The candidate
bytes matched the tested export. These tests made no native control writes or
test Job caps. Native guardian crash/reopen, supervisor, continuous host cohort
authority, P4 cost/shadow and P5/P6 acceptance remain outstanding.
