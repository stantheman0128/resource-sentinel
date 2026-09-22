# P4 retained asynchronous operator accept

This bounded implementation contract addresses the deterministic 50 ms idle
operator wait discovered while measuring the actual helper host. It changes
neither the formal P4 cost limits nor what work the measurement includes.
No native result, deployment, daily setting change or control promotion is
authorized by this document.

## Original listener operation

`NativePipeListener.poll_accept()` starts at most one original overlapped
`ConnectNamedPipe` operation and returns `None` while it remains pending. The
listener and capped process registry retain the original pipe, operation,
manual-reset event and storage before entering native acquisition or I/O.
Event acquisition and connect entry have their own pre-call attempt markers;
an interrupted acquisition without a returned handle remains an unresolved
original obligation and cannot be treated as an unstarted clean attempt.
Later polls only inspect that same operation with
`GetOverlappedResultEx(..., timeout_ms=0)`. They do not allocate another event,
reissue connect, cancel an idle listener, sleep, or wait for a timeout.

A positively completed connection retires its original event before returning
the same listener's borrowed `NativePipeConnection`. A connection already present
when connect is issued remains a valid early-connect result. Existing blocking
`accept(deadline)` keeps its existing behavior, but cannot overlap a retained
asynchronous attempt. There is still one listener instance and one active
borrower, with the existing endpoint/identity checks and registry limits.

The zero-time query behavior and required original OVERLAPPED/event lifetime
follow [GetOverlappedResultEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresultex)
and [ConnectNamedPipe](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe).
This uses overlapped I/O; it does not introduce `PIPE_NOWAIT` or a worker thread.

## Terminal stop and uncertain cleanup

`NativePipeListener.stop_accept()` irreversibly prevents another accept. It
returns `False` while the original accept remains pending and `True` only after
that operation/event has been positively retired and any connected success
race has been disconnected. The listener handle still requires its ordinary
explicit close. An active protocol borrower remains its original owner's
responsibility and cannot be discarded by stopping acceptance.

Stop records its cancellation attempt **before** entering `CancelIoEx`, issues
that call at most once per original operation, and subsequently performs only
zero-time completion observations. Cancellation acknowledgement and
`ERROR_NOT_FOUND` are not completion. Normal completion can win the cancellation
race; all outcomes keep the same operation and storage until positively known.
An unknown cancellation or observation keeps the owner quarantined and cannot
start another accept. This follows [CancelIoEx](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex).

Every event/pipe `CloseHandle` attempt also records a tombstone before entry.
Only an explicitly observed native BOOL-false result may permit a later close
attempt on that same original handle. A raised/interrupted call with unknown
outcome cannot be retried by an exception handler, `close()`, or registry reap;
it remains retained. A completed close clears the original handle before the
slot can be released. Existing documented-failure retry behavior is preserved.
The distinction comes from the actual native return boundary, not exception
text. See [CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle).

## Operator service and helper integration

`OperatorService.poll_once(listener, timeout_ms=50)` returns immediately when
no connection is ready. Once the original connection is delivered, it starts
one normal request deadline and executes the existing hello authentication,
request binding, challenge, handler and reply receipt protocol. The helper's
existing 50 ms connected-request timeout and all client deadlines stay intact.
Idle listening is a retained resource, not a repeatedly renewed RPC deadline.
Actual request work remains inside the measured helper tick.

The helper calls this polling API once per ordinary/drain tick. On final drain,
it settles `stop_accept()` **before** `HelperHost.close()` closes the original
telemetry sink and before releasing parent/process witnesses. A normal pending
cancellation keeps the host resident and is polled again; it is not mislabeled
as an unknown cleanup failure. Unknown cancellation, event/pipe close or peer
cleanup preserves the original error and custody. No helper replacement,
ordinary exit, or native-control conclusion follows from a pending stop.

## Required verification

Portable tests must cover repeated idle polls over the same operation/event,
zero native wait duration, one pending accept, early connect, completion and
cancellation races, terminal stop, pending-stop host residency, exact request
deadlines, authentication/reply behavior, and prior blocking accept behavior.
Add explicit known-BOOL-false versus success-then-interrupt close tests for both
event and pipe handles, including registry reap and exception cleanup paths.
Central regression includes every pipe transport and helper operator lifecycle
module. Portable fixtures prove these software contracts only; Windows-native
P4 overhead and capability evidence remain separate gates.
