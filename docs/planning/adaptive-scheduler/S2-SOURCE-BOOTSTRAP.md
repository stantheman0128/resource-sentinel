# S2 source binding and original console custody

Status: source integration, not a measured S2 capability gate. The normal S2
native runner and v2 publication remain refused until the original isolated
production-host/daily-demand scope below exists. Nothing here activates the
daily runtime, changes configuration, or creates an admission exemption.

## Connected source path

`tests/windows/run_adaptive_s2.py --check-source` executes the fixed parent
profile through `ProducerBootstrap`. It loads the actual launch producer,
fixture child and Win32 observation module from the reviewed producer root;
production modules come only from the canonical daily source root. The existing
S1 profile remains separate. Without `--check-source`, the S2 entry reports
`s2_original_production_host_scope_unavailable` before native work.

The real `produce_s2(..., bootstrap=original)` and `_run_case` consume that exact
retained parent bootstrap. They cannot manufacture it from a digest or callback.
Each new Python command uses the direct base interpreter with `-I`. The original
source/build/interpreter pin travels through the actual invocation chain:

1. Parent producer creates the console-driver command with `--source-pin` and
   includes the same pin in its bounded Base64 payload.
2. The console driver checks its own executed child profile against that pin
   before creating PowerShell. The PS bridge forwards `-I` and `--source-pin`
   to the real wrapper child. Baseline's outer admitted wrapper carries the
   same pin; it remains a semantics baseline, never an A0 performance baseline.
3. The actual wrapper command preserves the pin for the root workload; root
   passes the same pin and `-I` when creating a leaf. Workload stdin is untouched.
4. Each child executes the fixed bootstrap directly from its original main
   module frame, verifies canonical runtime and full producer inventories plus
   the base interpreter bytes, and refuses drift before new native work.

The pin is consistency data, not authority. It cannot supply admission, host
readiness, native membership, cleanup completion, or permission to launch.
No environment flag or source-check result unlocks S2. There is no ambient
repo `sys.path` override; exact source bytes are compiled under the restricted
import finder. Source drift must never disable original cleanup.

## Parent-local attempt contract

`S2CaseDeclaration` freezes case/mode/directory/token/stdio/source metadata.
`S2CaseAttempt` is published in `_CASE_ATTEMPTS` before an observer starts or
`Popen` begins. The exact driver argv and original observer are bound once before
creation. The same attempt retains the returned `Popen`, or an unknown creation
outcome when none returns. No PID adoption, new process, or replay is permitted
to resolve that ambiguity.

`observe_local_settlement()` requires the original thread and process objects,
positive exit, and successful close of the original Windows process handle.
Interrupted/unknown creation, observer start, or handle close stays retained;
a second native close cannot resolve an unknown close ACK. Diagnostic failure
cannot discard the original attempt. `S2CustodyPending.case_attempts` carries
those exact objects alongside any separate observer-handle uncertainties.

**Local settlement is deliberately not a whole-scope completion capability.**
A console exit, a fixture JSON file, or a closed parent observation handle does
not prove that production guardian bookkeeping, workload descendants, transport,
or original infrastructure ownership has settled. The registry stays in-process;
it is not a serialized retry token and does not itself release daily demand.

## Wrapper boundary

The fixture preregisters its host before `__init__`. An original native process
returned by `launch_in_job` is retained before timestamps/identity/provenance
or artifact writes; a subsequent failure transfers it to the real launcher
through `LaunchOutcomeUnknown`. Partial host or native construction stays held.

The resident cleanup loop continues despite logger failure, failed stop-file
publication, exception-accessor failure, interruption, or changed source. It
requires the original positive settlement receipt and closed local owners.
Python event output uses an owned append stream with `redirect_stderr`, so it
does not replace production `wrapper_host.emit` or alter native workload fd 2.
The NULL-stdin case restores the selector using the restored CRT fd's current
OS handle and verifies readback before reporting local cleanup.

## Exact remaining scope integration

The current S1 `ExperimentNativeScope.prepare` accepts only suite `S1` and a
`ScopeCommand`; `DailyExperimentDemand` registers that exact scope type and its
release consumes original `NativeScopeCompletion`. The S1 inert wrapper uses
`CREATE_NO_WINDOW`; wrapping the S2 console in that test Job would change the
measured topology. These APIs cannot be silently reused as production S2 proof.

The S2 provider must therefore supply a concrete retained scope with all of:

- The actual canonical daily demand and immutable reservation/source-generation
  binding held through every console, workload, observer, host and recovery
  obligation. Infrastructure estimates must be covered truthfully; the isolated
  ledger is never a source of capacity or an alternate admission provider.
- Original independently created Supervisor/Guardian and their descriptor in
  the isolated data directory. Replace the old producer assumption that
  `coverage.coordinator.db_path` identifies an already-running daily host.
  Do not discover or fault-test the daily production host.
- Exact registration of each `S2CaseAttempt` before any creation side effect,
  plus original production wrapper/guardian lifecycle evidence, real shared
  exclusions, and correctly reconciled cross-ledger allocations. The child
  currently requests 1 CPU / 256 MiB physical / 256 MiB Commit, independently;
  an umbrella reservation must not conceal or duplicate that accounting.
- Recovery and release derived from original native/transport/SQL ownership and
  guardian terminal receipts, not callbacks, arrays, filenames or booleans.
  Parent `local_settled` is one input only. Preserve unknown partial acquisition
  and demand until the full original completion contract positively holds.
- One full measured same-topology matrix per installed supported shell: 79
  canonical records, including 20 fast-exit and 20 child-survival records.
  Secondary console/null profiles remain partial diagnostics. Only the full
  reducer and original provider completion may authorize future S2 publication.

The fixed policies remain 58 GiB / 4 GiB physical / 4 GiB Commit / three user
leases. This slice adds no CPU control, kill-based scheduler recovery, suspend,
RAM cap, automatic exemption, alternative ledger admission, or deployment.

## Verification ownership

Portable verification modules: `tests.test_adaptive_producer_bootstrap`,
`tests.test_adaptive_s2_bootstrap`, `tests.test_adaptive_launch_producer`, and
`tests.test_adaptive_s2_wrapper_custody`. Source checks execute isolated copies
of the actual fixed closure; custody cases use explicit portable fault models.
They do not establish Windows launch semantics or any S2 native gate. The author
of this slice performed static diff inspection only; central test results must
be recorded separately after the coordinated runner executes them.
