# Original Job security observation and cleanup custody

Contract before source implementation, 2026-09-24, after `1e105b6`.
This is a data-observation prerequisite for the serial S1 provider, not provider
integration, native evidence, capacity authority or production activation.

## Actual source gap

`windows._WindowsMutexBackend.verify_security` already reads `GetSecurityInfo`
on the supplied handle and strictly parses the descriptor owner, protected DACL,
one explicit allow ACE, logon SID and exact mask. It returns no parsed record.
`NativeJob._verify` invokes that parser and `GetHandleInformation`, but a later
consumer cannot request the actual observation. The older test adapter's
`OwnedJob.security` dictionary consists of assumed constants; this slice neither
uses nor changes it.

Three actual custody gaps affect a new observation path:

- `_owned_resource` retains cleanup failure only when the body already raised.
  Its normal-exit release can fail without retaining that descriptor/SID owner.
- `_RetainedNative.close` repeats a release after any exception, including an
  unknown native outcome.
- `_security_call` translates a `NativePolicyMutexError` to `NativeJobError`
  while copying only notes and suppressing its cause. A Job's `closed` property
  currently accounts only its own descriptor/creation/retained handle resources.

The security path also calls `OpenProcessToken`, `ConvertSidToStringSidW` and
`GetSecurityInfo` before publishing output custody. An interruption at one of
those allocation calls must not become proof that no owner was acquired.

## Exact data API

Add frozen `windows.SecurityObservation` with these fields:

```
owner_sid: str
logon_sid: str
descriptor_control: int
descriptor_revision: int
acl_revision: int
ace_count: int
ace_type: int
ace_flags: int
access_mask: int
```

All values come from this invocation's successfully parsed native buffers.
`verify_security` returns that value only after the enclosing descriptor and
both SID string conversions have positively released their original owners.
Its existing exact owner/logon/mask/ACL checks remain unchanged. Existing
constructor callers may ignore the new return value.

Add frozen `native_job.JobSecurity` with the same nine fields plus
`handle_flags: int`. `NativeJob.query_security() -> JobSecurity` runs under the
existing original object's lock, requires its live retained handle, calls the
actual current-owner/parser path and `GetHandleInformation` on that exact
handle, and returns fresh data. It never reopens by name/PID, sets security,
changes CPU state, or reconstructs a result from successful construction.

The query requires the exact typed `SecurityObservation`, exact scalar types
and existing strict expected values; bool is not an integer observation.
Constructor fixture verifiers returning `None` remain compatible with create
and open, but `query_security` refuses unavailable typed observation. No new
callback, serialized authority, observation cache or factory token is added.
These dataclasses are observations, not launch, cleanup or admission authority.

An inheritable handle remains a refusal. Preserve actual handle flags in the
successful result rather than reporting a manufactured `noninheritable=True`.
Queries after close or while security acquisition/cleanup remains unresolved
refuse before another native acquisition. A later query observes mutations;
an earlier frozen record is only the earlier observation.

## Minimal original resource accounting

Keep the existing `_policy_mutex_cleanup` owner attachment and settlement API;
do not introduce a second cleanup framework. Strengthen its private retained
owner with explicit owned/allocation-unknown/close-unknown/closed state and a
positive-closure predicate. Publish the original output cell before each of the
three security allocation calls above. A documented unsuccessful result supplies
no trusted output; an exception after entry retains the original output cell in
allocation-unknown state. Unknown output is never interpreted as a handle to
close. Positive allocation transitions that same owner to owned.

`_owned_resource` must use that original owner through body and normal exit.
Both body-plus-release failure and normal-exit release failure attach the same
owner and preserve the original exception; the latter raises its original
cleanup exception. Nested SID/descriptor failures retain all original owners.
Success publishes the closed tombstone before dropping the value.

The concrete Windows `close` and `free` adapters stamp an exact
`_known_native_close_failed = True` only after documented CloseHandle FALSE or
LocalFree non-NULL return. They mark raised native-call outcomes unknown. Only
known failure permits retry on the same retained owner; unknown release never
repeats the kernel call, even if a fixture later stops raising. Settlement never
repeats source verification or adopts a new allocation. Do not infer known
failure from a sanitized reason string alone.

Two existing `RetainedNativeCustodyTests` in
`tests/test_adaptive_policy_mutex.py` deliberately model documented close/free
failure by constructing `NativePolicyMutexError` directly. They will need the
explicit known-failure stamp in those synthetic release functions. Root must
own/approve those minimal fixture edits because they are outside this worker's
assigned files. Existing notes and same-owner retry assertions remain intact.

## NativeJob error and closure accounting

Retain translated security errors through a direct original exception link
(`_native_job_security_error`) and an explicit cause; preserve exact retained
owner attachments, not just note strings. Raw interruption exceptions remain
the original exceptions with their attached acquisition/cleanup owners.

The Job retains its first unresolved original security-error graph. Constructor
failure and query failure both reach that same accounting path. A failed query
with outstanding owners also attaches this exact Job under `_native_job_cleanup`
so existing callers retain custody. Requery is blocked while it is unresolved,
bounding outstanding observation acquisitions instead of accumulating retries.

`NativeJob.close()` may settle only those original known-owned dependencies and
its existing original handles. An unknown security allocation/release cannot be
retried and keeps `closed == False` even if the Job handle itself closes. A
documented failed free can be retried on the same resource by explicit cleanup;
after every dependency and Job handle closes positively, ordinary closure can
succeed. A clean parse/validation rejection with positively closed dependencies
does not itself manufacture an outstanding resource, and grants no observation.
Restoring via an independently retained valid principal is not changed here.

## Owned patch and focused verification

Worker source ownership remains only `sentinel/adaptive/windows.py`,
`sentinel/adaptive/native_job.py`, and new
`tests/test_adaptive_job_security.py`. No provider, wrapper, schema, receipt,
runtime or source-manifest changes are included. Root owns public contract,
integration, any approved existing-fixture adjustment, test execution and commit.

New portable tests use explicitly supplied kernel/advapi objects and real ctypes
descriptor/ACL/ACE/SID buffers. They exercise the actual strict parser, original
NativeJob owner and native cleanup code without WinDLL or OS objects:

- Frozen complete observation and exact raw fields; original handle only;
  no Open/Create/Set or constants inferred from constructor success.
- Invalid owner, logon, descriptor controls/length, ACL shape, ACE count/type/
  flags/mask and inheritable handle; exact integer/string output types.
- Fresh mutation requery, no typed result for legacy `None` fixture verifier,
  and post-close refusal without additional native calls.
- Descriptor/SID cleanup failure after otherwise successful parse; simultaneous
  parse and cleanup failure; original causes/owners survive translation.
- Known failed release retries the same original resource; unknown release and
  interrupted acquisition retain original custody with zero repeated native
  release/acquisition; successful Job-handle close does not hide dependencies.
- Constructor-failure compatibility and shared mutex retained-owner behavior.

Root centrally runs the new module plus native Job, policy mutex, preparation,
probe and original release regressions under normal admission. No native tests,
imports or runtime execution are authorized for this worker. Passing portable
tests will establish source behavior only; actual native security observations,
serial S1 integration and all native gates remain unverified.

