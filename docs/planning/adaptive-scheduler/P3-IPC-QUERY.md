# Native IPC query dependency

Date: 2026-09-20. Base: `b0596d035dd83fe6870ab77a5ab70e383d2ff349`.
Adaptive remains off. This implements the authenticated local query transport
needed by P2 handoff and P3 IPC; it is not a completed launcher, guardian, native
lifecycle, capability gate or CPU-control release.

## Actual consumer and credential boundary

`ManagedExecutionClient` queries its live `ManagedAdmission` through a native
Named Pipe. `LifecycleQueryService` supports only `QueryExecution` and
`GetReadiness`, for that context's own admitted direct execution. Unsupported
operations are rejected before reading authentication material. No endpoint
starts a collector, creates a reservation, changes a lease, launches work or
writes an OS restriction. Every reply explicitly retains admission-only,
unverified native readiness and unverified OS-limit state.

The caller receives `NativePipeEndpoint` from a trusted bootstrap with the full
server PID, integer creation FILETIME and logon SID plus random instance UUID.
This component does not yet implement production endpoint discovery, guardian
epoch publication or restart recovery. A server's own hello is not a source of
trust. The native client checks the expected server before sending its execution
selector, and retains the verified server handle throughout the connection.

Admission creates a separate 32-byte query key, binds it to the immutable
admission digest, and writes it in the same transaction as the RESERVED row.
It is a shared secret, not a public verifier. Public lifecycle ACKs and queries
exclude it, as does snapshot repr; generic snapshot-to-JSON serialization fails
closed. Old rows with NULL keys cannot silently acquire new authentication.
Retries must match the original key and allocation. A closed context cannot sign.

The launch claim is never exported or consumed for a read query. An authenticated
query therefore preserves the existing unused-claim cancellation guarantee;
the context can also authenticate terminal readback after that cancellation.
No key revocation, new launch grant or capacity release is inferred from a pipe
failure, dead peer, timeout, handle close or unsuccessful receipt.

One necessary digest refinement separates these capabilities:
`prelaunch_record_hash` excludes the raw query key, which has no launch custody
authority and is absent from public snapshots. The admission binding hash remains
in the custody digest and includes the key. Admission replay compares the stored
raw key; final query readback revalidates the complete original auth tuple. This
prevents a private BLOB from breaking prelaunch cancellation while preserving
its existing launch and allocation checks.

## Protocol and native ownership

Frames are little-endian 32-bit lengths followed by strict UTF-8 JSON, with a
256 KiB payload limit checked before body allocation. Duplicate fields, nonfinite
numbers, unsupported major versions, unknown keys and malformed typed identities
are rejected. Query request IDs are canonical UUIDs and scope each exchange;
retrying a read obtains current state with a new challenge, not a cached launch
authorization. Future mutation routes still need their own durable idempotency
contracts and must not cache an old `launch_authorized=True` ACK.

For each connection the server obtains the wrapper's exact identity from the
admitted row, compares the pipe's OS-reported client PID, requires ALIVE before
authentication/readback/result transmission, and retains that exact
`VerifiedProcess` through the short read transaction and receipt.
A fresh 256-bit challenge is used once. Domain-separated HMAC transcripts bind
the full request, endpoint instance, both native identities and challenge;
different domains authenticate proof, result and receipt. Failed exchanges are
closed, not resumed with the same challenge. Final readback compares the auth
tuple and reads the sanitized own row in one read-only transaction. No SQLite
transaction waits on pipe I/O or native process verification.

Both sides use the same absolute deadline across all phases. Default queries
allow 1 second, explicitly bounded to at most 5 seconds; each DB read receives
at most 250 ms of the remaining budget. This is not the future `GetFastFrame`
250 ms contract, which is not implemented here. A receipt confirms the client
consumed and authenticated the response before the server disconnects. That
authenticated receipt is the read-only completion point: the client may then
close or exit, so no new live-pipe/PID check invalidates the completed read. The
held identity handle still unwinds normally. There is no potentially unbounded
`FlushFileBuffers` wait.

The reusable listener retains one FIRST_PIPE_INSTANCE handle, with a protected
single-logon ACL, remote-client rejection and non-inheritable handles. A client
requests identification SQOS. Security readback uses pipe-specific access rights;
the policy mutex's existing default rights remain unchanged. Each endpoint has
one active connection and no application waiting queue. A process-wide registry
caps all retained listener/client owners at 128, including across custom registry
instances and including idle listeners and uncertain cleanup. This conservative
resource bound is stricter than counting only authenticated requests.

Buffers, OVERLAPPED structures and events are strongly retained before native
I/O starts. `CancelIoEx` requests cancellation; it does not establish completion.
An uncertain original operation poisons the endpoint and retains its resource
slot. Bounded reaping observes that same operation without resubmission and
releases storage only after terminal completion. Failed native close/disconnect
also retains ownership, marks quarantine and permits later bounded cleanup.
Normal busy/proof-scope rejection does not poison an in-use connection.

Deadlines use sleep-inclusive `GetTickCount64`, finite native wait slices and
post-completion checks. Kernel/filesystem stalls, scheduling and local
`CreateFileW` cannot provide a hard wall-clock completion guarantee. A held
process handle does not guarantee survival after the last observation. Native
pipe PID queries do not identify a different same-user process that inherited
or duplicated the handle. This remains same-user governance, not a security
sandbox against a hostile user who can change the ledger or duplicate handles.

The native semantics follow Microsoft's
[Named Pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights),
[ConnectNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe),
[CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex)
and [GetOverlappedResultEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresultex)
contracts. Source inspection is not a substitute for the native tests below.

## Verification and remaining gates

Environment: Windows 11 build 26340, x64 Python 3.13.3. Tests used the normal live
Sentinel P2 wrapper with 1 CPU unit, 0.75 GiB RAM and 0 IO slots. The first command
waited for Commit capacity and resumed through normal admission; no estimate,
policy or exemption changed. `SENTINEL_ADAPTIVE_WINDOWS_SPIKES=0` kept Job/control
spikes disabled. Native IPC tests need no Job opt-in.

| Run | Result |
| --- | --- |
| Focused credential/context/admission/cancellation integration | 96 passed in 2.909 s; zero failures/errors/skips |
| First clean IPC/pipe/native candidate | 70 tests in 2.894 s; two protocol fixture errors; zero failures/skips |
| Corrected clean full regression | 528 passed in 33.060 s; zero failures/errors/skips |

The two first-run errors constructed UNKNOWN identity observations without the
required reason, failing before the intended IPC guard. Only those fixture
constructors changed; expected rejection, zero-dispatch and no-receipt assertions
remained intact. All six native IPC tests and all 27 portable pipe tests had
already passed that first run. The final candidate is exact Git tree
`f1e6f76d2e71e6207b7c9c316abd6cf2bf20734c`; every staged source/test blob matched
its clean export. Only evidence documentation was finalized afterward.

The final 528 cases comprise 512 portable tests and 16 Windows native tests,
including six new native IPC cases. New coverage includes 27 admission-auth
cases, 37 protocol cases and 27 pipe ownership/API-argument cases. The native
cases exercise actual same-process and cross-process server/client transport,
exact peer pinning, own execution/readiness queries, preserved unused-claim
cancellation and terminal readback, partial-frame/idle deadlines, eventual
cleanup, reusable pipe names, and a voluntary child server's natural exit.
Successful query groups compare the entire isolated ledger's logical digest
before and after. Native resource cleanup assertions and thread joins passed.

The full command was:

```powershell
py -X utf8 -m unittest `
  tests.test_adaptive_prelaunch tests.test_adaptive_lifecycle `
  tests.test_adaptive_accounting tests.test_adaptive_maintainer `
  tests.test_adaptive_coordinator tests.test_adaptive_contracts `
  tests.test_adaptive_query tests.test_maintainer tests.test_coordinator `
  tests.test_orchestrator tests.test_adaptive_allocation_transitions `
  tests.test_adaptive_identity tests.test_adaptive_admission_context `
  tests.test_adaptive_managed_admission tests.test_adaptive_evidence_scope `
  tests.test_adaptive_legacy_mode tests.test_adaptive_native_cancel `
  tests.test_adaptive_policy_mutex tests.test_adaptive_policy_scope `
  tests.test_adaptive_ipc_admission tests.test_adaptive_ipc `
  tests.test_adaptive_pipe_windows tests.test_adaptive_native_ipc
```

Portable fault injection proves original pending storage is retained across
unknown cancellation/cleanup outcomes and later released on positive completion.
The real timeout tests permit either immediate cancellation or later reaping;
they do not prove that rare delayed-cancellation quarantine occurred natively.
Actual separate-logon/remote-host attack attempts, hard wall-clock bounds across
kernel stalls, production guardian discovery and P4 monitoring overhead remain
unverified. Test duration is not an overhead or workload-performance result.

All three exact normal test reservations were verified absent. The 35 tracked
daily runtime source paths and production configuration hash remained unchanged.
No Job, CPU cap, exemption, Scheduled Task, resident daemon, production deployment
or global agent-policy update was created by this slice. The installed 104 skill
hashes still matched validated artifacts and the global MCP entry remained off.

The existing full native lifecycle and P3-P6 gates remain unsatisfied: an unknown
inherited foreign Job and absent verified continuous daily reservation-floor
coverage prevent the controlled Job spikes. This slice does not remove that
guard or deploy a new daily runtime. Launcher atomic containment, guardian
ownership/recovery, exemption and legacy-writer participation, fast sampling,
shadow overhead, single-Job control canary and real-command A/B remain required.
The canonical agent-policy/bootstrap entrypoints are unchanged by this slice.
