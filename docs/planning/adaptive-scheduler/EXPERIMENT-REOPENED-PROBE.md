# Original S1 scope: reopened Job probe and restore

Status: source implemented with synthetic-backend regression evidence; native
acceptance remains unverified. The prior contract was committed as `c59376a`,
after `178c2e4`. This closes a concrete
serial-provider prerequisite: S1 must actually reopen a Job handle and restore
through that handle. The original principal remains retained throughout. No
production activation, new restrictive actuator, or native gate is granted.

## Bounded ownership and APIs

Add `ExperimentNativeScope.open_probe()`, `close_probe(probe)`, and
`restore(through=None)`. A probe is an exact retained `NativeJob` opened with
CONTROL access for this registered scope's exact name, nonce and logon identity.
Opening validates the original scope/principal and runs under isolated POLICY
then Job lock, without daily RPC/SQL or a new admission. It creates no workload
and changes no CPU state; an expired daily lease does not block restore access.
Do not open after scope closing has begun or the principal is unavailable.

At most two total native probe-open attempts and one live/unsettled probe per
scope. This supports one initial observation handle, its positive close, then
one actual reopened handle for the S1 restore check. These are handles to the
same Job, not two Jobs. No failure resets the attempt count or grants a retry
with a new object. A new experiment can start only after original full cleanup.

Register each attempt before entering `NativeJob.open`. Retain its sequence,
original returned object or original initialization exception, exact binding,
and cleanup state. A factory error must retain the unique matching concrete
owner from `_native_job_initialization_owners`, even when already closed. No
returned owner and no original factory evidence means unknown, not absence.
Keep the original attempt graph; replacement, duplicate owners or inconsistent
sequence/count refuse. Never reconstruct custody from JSON or handle numbers.

The principal must stay open while opening/using probes, so a name cannot refer
to a replacement Job. Verify native security through the existing NativeJob
factory and compare principal/probe limits and canonical CPU state before use.
`close_probe` accepts only the exact scope-owned returned probe, never the
principal, a copy, another scope's object or a merely equal name. Closing an
already positively closed original is idempotent. Known close FALSE can retry
the same original owner; unknown native close is not retried/reopened.

## Restore and cleanup

`restore()` keeps its existing isolated-only behavior. `restore(through=probe)`
requires an exact live probe from this scope and validates both observations
under the same isolated POLICY/Job locks. Persist the existing restore intent,
close SQL, disable through the probe, then query both probe and principal as
disabled before acknowledging. Preserve the existing external-control conflict
checks and intent on query/Set/ACK failure. No SQLite transaction spans native
calls. Daily readiness/TTL loss never blocks original restore.

Probe trouble does not prevent a valid principal-only restore. It does prevent
new restrictive Set, new probe acquisition, capacity release and successful
completion while any original acquisition/close remains unsettled. Cleanup
always retains the daily demand floor; closing a probe is neither Job empty nor
capacity release. Before closing the principal, close every original returned
or failed-initialization probe positively. Partial cleanup resumes only those
same owners. Completion validation checks the complete original probe graph,
including on later replay, and never claims an unknown open was absent.

## Completion data compatibility

No-probe completions retain their exact existing schema version 1. A scope with
one or two probe attempts emits completion version 2 with one additional field,
`probe_custody`: an ordered list of exact `{ordinal, outcome}` entries. Ordinals
are integers (not bool), contiguous from 1; outcome is `opened_closed` for an
original returned owner or `failed_closed` for an original factory owner whose
cleanup was positively verified. No other state can mint completion. Version 2
is restricted to registered `NEVER_LAUNCHED` or `FINISHED` scopes; early native
preparation and BEFORE_NATIVE paths never acquire probes.

The closure digest covers this summary. History accepts exact version 1 shapes
unchanged and exact version 2 shapes with one or two valid entries; it rejects
unknown fields/version, empty/oversized lists, duplicate/out-of-order ordinals,
unknown/live outcomes and use on another disposition. Receipt schema, daily
terminal state, cancellation/archive and exclusion cleanup remain unchanged.
This persisted summary is data; release still needs the original completion.

## Evidence and boundaries

Tests must exercise actual original scope preparation and isolated SQLite with
explicit synthetic native APIs: original principal retained, one-live/two-total
bound, exact foreign/copy rejection, failed-open owner retention, known FALSE vs
unknown close, true selected-handle restore and dual readback, lost ACK intent,
restore after readiness loss, completion refusal until all probes close, and
version 1/2 history compatibility and tamper rejection. Run shared scope,
release/history/readiness and native Job tests through normal daily admission.

These tests prove source contracts only. Real reopened-handle CPU effect,
serial-provider integration, root/child deadlines, S1-S3, overhead and P6 A/B
remain unverified or unfinished until their actual evidence exists.

Implementation review additionally found that a retained factory exception can
carry multiple owners. Validation now compares its entire matching CONTROL-owner
graph to the original failed attempts, rejects extra/duplicate owners even on
completion replay, and allows one exception reused by two original failed opens.
Probe-native errors are retained before isolated lock cleanup and deferred until
positive scope exit; genuine POLICY/Job-lock cleanup failures still propagate.
This preserves principal-only restore without treating unknown cleanup as done.

The two new test files contain 30 cases. Initial history/consumer verification
passed 50 tests; the focused seven-module scope/history/native Job run passed
158 tests, with zero failures, errors or skips. Final shared regression and the
reproducible admitted command are recorded in the planning README. Tests use the
protected local dirty baseline; they are not a clean-checkout full-suite claim.
