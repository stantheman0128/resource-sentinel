# S1 recovery consumer and native power observation

2026-09-20. S1 previously released a verified-restored control slot into
`RECOVERY_HOLD` without a consumer that could complete the five-window warmup
and accounting reconciliation. The actual `S1Runtime` / `S1ExecutionOwner.close`
path now performs that work before it closes original native custody handles.
This is test-host implementation, not a production guardian or native P1 pass.

## Implemented path

1. Include every execution owned by this serial S1 run and the complete bounded
   registry, including historical terminal rows and the persisted control slot.
   Missing or additional registered scopes are unresolved. An empty active-row
   query, RESTORED slot or failed reopen cannot prove all limits are withdrawn.
2. Under the actual POLICY and Job mutation scope, verify the exact owner,
   original Job handle, disabled CPU control, sealed/terminal lifecycle, empty
   accounting and PID list, root exit where applicable, and settled durable
   journal. A closed historical owner needs the private witness previously
   created under its original custody; a serialized receipt cannot replace it.
3. Register a real Windows suspend/resume observer, invalidate the sampler's
   baseline, and collect five new one-second uncapped windows. Native sampling
   and waits occur outside POLICY/Job/SQLite scopes. Every window rechecks
   inventory, control, journal, runtime/config identity and power generation.
   A reset, stale sample, observed power event or 12-second observation deadline
   failure aborts the attempt; it is not silently retried into a passing result.
4. Recheck the final host/config state, then run `project_local_capacity` in the
   same short transaction as the registry-revision CAS from RECOVERY_HOLD to
   NONE. Freshness and the power token are checked around projection and CAS.
   Native queries and waits stay outside the transaction. Empty attribution
   subtracts no measured usage and preserves other real ledger allocations.
5. Unregister the observer after releasing mutation locks. Only successful
   observation cleanup publishes a reusable in-process settled-owner witness.
   The owner then closes its retained handles. Partial handle cleanup can retry
   from that completed proof without querying a closed root or reacquiring a
   closed mutex. Handle close itself never creates that proof.

`tests/windows/adaptive_recovery.py` implements this consumer;
`tests/windows/adaptive_execution.py` wires it into actual owner cleanup and
rejects opening the next case while a previous owner remains unsettled.
The [machine sampler](P1-MACHINE-SAMPLER.md) supplies real bounded machine
endpoints. The injected backends used by portable tests are not a native entry
unlock or host readiness authority.

## Native notification custody

`tests/windows/adaptive_power.py` registers through
[PowerRegisterSuspendResumeNotification](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification).
The callback only invalidates in-memory continuity. It performs no SQL, Job
mutation or power-state change. A retained callback trampoline and never-reused
opaque contexts avoid dereferencing retired callback state.

Cleanup calls
[PowerUnregisterSuspendResumeNotification](https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerunregistersuspendresumenotification),
not CloseHandle. A confirmed failed unregister can retry the same owned
registration. An unknown completion cannot safely reuse a possibly retired
registration, so it retains roots and remains unavailable. Failed registration
with a non-null output also does not establish ownership. Recovery retains a
failed-open witness instead of creating another registration over uncertainty.

Successful barrier CAS is the completion point for the verified recovery
evidence. A later observer-unregister failure retains the owner and attempts to
re-enter HOLD; NONE may already have been visible after that successful CAS.
There is no claim that a later observation-cleanup error retroactively invalidates
the earlier Query-disabled/empty/accounting proof. The next S1 case remains
blocked until exact cleanup succeeds. If a commit acknowledgement is lost,
the owner and mutation-fence recovery path retain that uncertainty.

## Validation

All commands used Windows x64 / Python 3.13 and the ordinary daily Sentinel
wrapper at P2, CPU 1, RAM 1 GiB, I/O 0. Tests ran in exact Git-index exports;
portable native collaborators and SQLite data were isolated. No test Job, CPU
cap, workload process or test Scheduled Task was created. Native Job-spike
opt-in remained zero; real sleep/resume was not requested.

The power observer's final source/test candidate
`5bc68ee2340c5ecc7c99ae65cfde81e07348f172` passed **22 tests, 0 failures/errors/
skips**, including one actual Windows register/snapshot/assert/unregister
smoke. It makes no native callback-delivery or sleep/resume recovery claim.
An earlier 20-test candidate also passed; two ownership-uncertainty regressions
were then added after review and the final candidate was rerun.

```text
python -m unittest tests.test_adaptive_power tests.test_adaptive_power.NativePowerWitnessSmokeTests.test_native_register_snapshot_assert_unregister
```

The recovery integration candidate `f8dfacd2611e854dc3e116dd4b2c2552e94140f8`
ran 264 tests: 263 passed, one new-test error, zero skips. That fixture deleted
the execution but left its restored control slot, so the earlier exact slot
binding check correctly rejected it before the expected inventory check.
The final tests separately verify that earlier rejection and a genuinely empty
registry/slot, retaining the HOLD and open-handle assertions in both cases.
Production source was unchanged by this fixture correction.

The final source/test tree `1409d72dcd27f208a7d920df322913d180a6f84c`
reran the complete affected recovery module: **32 passed, 0 failures/errors/
skips**, 13.709 seconds. The other 233 tests passed in the preceding run against
the identical source. These are two recorded runs, not a claim of 296 unique
tests or a second full-suite execution.

```text
python -m unittest tests.test_adaptive_recovery tests.test_adaptive_power tests.test_adaptive_machine_sampler tests.test_adaptive_execution_owner tests.test_adaptive_control_authority tests.test_adaptive_s1_owner_integration tests.test_adaptive_accounting tests.test_adaptive_control_slot tests.test_adaptive_policy_scope tests.test_adaptive_ledger_coverage
python -m unittest tests.test_adaptive_recovery
```

## Scope and remaining gate

This consumer deliberately handles serial S1 cases that have reached verified
terminal/empty state. It is not the production guardian's recovery of still
running background commands. Its bounded historical inventory is not a change
to the ten-enrolled/one-capped policy. The machine budget, both reserves and
three-user-exemption limit are unchanged.

The default native entry still lacks a real running host/cohort authority, and
the previously tested host launch paths inherit an unknown foreign Job. These
are separate gaps; the source prerequisite above does not make either pass.
Production launcher/guardian/supervisor, complete loaded-writer handoff, fast
helper overhead, native fault recovery and P6 paired A/B remain unfinished.
Daily runtime stays unchanged and adaptive remains off. No new environment
flag, receipt or mock unlock was introduced to cross those gates.

Post-run verification found no remaining exact test reservations; all 35
previously recorded daily source paths and the runtime configuration hash were
unchanged. Private logs retain every candidate/result without publishing config,
database contents, user process identities or the protected incoming diff.
