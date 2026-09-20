# Helper-to-guardian control proposal transport

2026-09-21. A P3 implementation slice on branch
`codex/adaptive-scheduler-implementation`. Adaptive stays off. Nothing here is
deployed, no configuration can select canary, limited or enforce, and this is
not a P4, P5 or P6 gate pass.

## What exists now

`sentinel/adaptive/proposal_builder.py` turns one `decision.Decision` into a
typed `ControlProposal`. It is pure: its only imports are `contracts` and
`decision`. Every epoch, revision, sequence number and sample identifier is an
explicit keyword, a missing one is a `TypeError` and a wrong one is a typed
refusal. It returns None for OBSERVE and NO_POLICY_ACTION, it requires the
applied target to be supplied for a RENEW because a renewal decision carries no
target of its own, and it refuses a decision that is not executable, so a shadow
run stays structurally unable to emit control. helper.py imports neither this
module nor the transport, and a test asserts that.

REQUEST_RESTORE has no proposal form. `GuardianControl` refuses every target
whose mode is not `hard_cap` and withdraws a cap through its own
`request_restore` entry point, so a restore proposal would be a message that is
always rejected. The builder refuses to build one instead of imitating a path
the contract cannot express.

`sentinel/adaptive/control_transport.py` carries that proposal. It has the same
shape as `ipc.LifecycleQueryService` and `launch_transport.LaunchService`:
`ControlProposalService(db_path_or_store, endpoint, control).serve_once(listener,
timeout_ms=...)` authenticates the caller first, then reads one length-prefixed
frame, validates it with `ControlProposal.from_dict`, calls `control.apply`
exactly once and returns the `ApplyAck` it sent back. The helper's identity does
not depend on the request, so a peer that is not the registered helper is
refused before any request byte is read. `ControlProposalClient`
pins the server process before writing, checks the challenge binding, and checks
that the acknowledgement is bound to the proposal it sent.

The service grants no authority. It never reads the ledger mode, never short
circuits an apply, keeps no acknowledgement of its own and holds no lease. A
retried request id is answered by `GuardianControl` with the original
acknowledgement, which is the only correct cache for it. The only thing the wire
can carry is the typed contract, so there is no arbitrary PID and no arbitrary
SetInformation class to pass.

Limits taken from plan section 5.5: the 256 KiB `MAX_MESSAGE_BYTES` cap, refusal
of any protocol major other than 1, one bounded `NativeDeadline` shared by every
phase of the exchange, one connection at a time, and a deadline recheck before
and after each read, each write and the owner call.

## Authentication, and the plan clarification to confirm

The caller must be the process registered with role `helper` for the endpoint's
logon in `adaptive_infrastructure`, and that row is the only authority on who the
helper is. The registry is read in a short bounded read-only snapshot through
`store._ipc_read_transaction`, which is released before the native peer handle is
opened, so no transaction is held across a native call or across `control.apply`.
The identity from that row is then proven with `connection.verified_peer`, with
the same liveness recheck the other two services use before and after the owner
call. A PID reported inside JSON is never trusted. No registered helper, more
than one candidate row, a registry that is absent, a registry whose columns do
not match `_INFRA_COLUMNS`, a row with the wrong schema version, an unparsable
identity, or a row naming the guardian itself: each is a typed refusal, and
`control.apply` is not called.

Plan section 5.5 (`IMPLEMENTATION-PLAN.md:395`) asks for the caller to be bound
by an OS verifiable identity and a one-time token. There is no shared secret
here. The wrapper RPCs sign transcripts with the execution's `ipc_auth_key`, but
the helper owns no such key, and the registry schema is fixed by
`_INFRA_COLUMNS`. Adding a column, a table or a boolean to give the helper a key
would invent an authority record that nothing issues, so this implementation
satisfies the requirement with the OS verified peer plus a per-request server
nonce bound to the request id, the endpoint instance, the guardian epoch and both
process identities. The nonce is not a secret and proves no shared key: it exists
so a response cannot be correlated to another request, another endpoint instance,
another guardian epoch or another pair of processes. The guardian's own
`ipc_auth_key` is deliberately not reused, because it belongs to a wrapper
execution and not to this exchange.

**This is a plan clarification the repo owner must confirm.** If a real shared
secret is required for the helper, it needs an authority that issues it and a
record that stores it, and both are out of scope here.

## Outcome uncertainty

The client sends one proposal and returns one acknowledgement. It never retries
by itself and never invents a new request id or decision sequence: a retry is the
proposer's decision and must reuse both, so the guardian can answer with the
original acknowledgement. From the moment the write is entered, any later failure
is reported as `outcome_unknown`, including a deadline reached at the write
boundary with no byte sent. That direction is deliberate, because the opposite
error would let a proposer conclude that a proposal never arrived.

An acknowledgement whose request id, execution, guardian epoch, policy epoch or
decision sequence does not match the proposal is refused on both sides and never
reaches the caller as a parsed result. A guardian that refuses a stale guardian
epoch answers with its own epoch, so such a refusal fails this check and the
proposer has to resynchronize rather than read an acknowledgement it cannot bind.

## What is not delivered

The guardian side is wired and the helper side is not. `guardian_host.py` builds
the service on a third pipe endpoint after the control consumer exists, serves at
most one proposal per iteration, records only the execution, result and reason of
the acknowledgement, and closes the listener with the other two. While draining
it serves neither launches nor proposals, so an unserved renewal lets the lease
run out and the expiry sweep restores the cap. The three pipes are served one
after another, each with its own bounded deadline, which is a property of the
loop and not a measured reaction time.

`GuardianControl.apply` turns a `LifecycleError` into an acknowledgement. The
host loop catches pipe, IPC and lifecycle errors from a served proposal and
reports them. Any other exception out of `apply` is not caught and ends the
guardian process, the same fail-stop choice the host makes for `control.tick`,
so that a verified death lets the supervisor restore.

The transport inherits the trust of `adaptive_infrastructure` and adds none.
Whatever can write `sentinel.db` under the policy mutex can register a helper
row.

There is no resident helper host process: nothing
enrolls Jobs, runs the sampler, drives the decision loop or holds an episode
across ticks. There is no endpoint distribution or bootstrap, so nothing tells a
helper which endpoint instance to connect to. There is no restore path over the
wire, by the design note above. Nothing registers a helper in
`adaptive_infrastructure` outside tests.

No native evidence. This machine runs inside a foreign parent Job, so the native
host check refuses and the native pipe path cannot execute here at all. Every
claim below is portable evidence on synthetic backends.

## Tests and their labels

`tests/test_adaptive_proposal_builder.py` is pure. Its decisions come from the
production state machine through the shared fixtures in
`tests/test_adaptive_decision.py`. It builds the enforce profile in memory;
`validate_policy_profile` still refuses enforce from a configuration file, and no
configuration is read or written.

`tests/test_adaptive_control_transport.py` covers the service and client
refusals: no helper registered, a process registered under another role, two
registered helpers, an unavailable registry, a malformed registry, a peer that is
not the registered process, an exited or unknown peer, malformed and cross-bound
frames, an oversized frame, a version mismatch, a challenge binding mismatch, an
acknowledgement binding mismatch on both sides, a deadline expiry before the
owner call, and the unknown outcome classification.

Its three end-to-end cases run the real client, the real service and the
production `GuardianControl` against a real isolated SQLite ledger, the
production store, control slot, policy coordinator, recovery journal and
exemption ledger on real temporary files: ledger mode off is REJECTED with zero
Job Set calls, an eligible canary ledger is APPLIED once and a retried request id
returns the same acknowledgement with no second Set, and an unregistered caller
is refused with zero calls into `GuardianControl`.

The pipe connections, the Job, the processes and the mutexes in those tests are
explicitly synthetic: they model completed byte transfers, answer queries and
count calls, and they contain nothing. Every ledger mode write is a fixture write
into an isolated test database. Passing is evidence about this transport's
authentication and binding decisions, not about Windows Job containment, host
support, native pipe I/O or timing.
