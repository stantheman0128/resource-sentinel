"""Portable retained-peer transfer failures, never authenticated native proof.

Automatic tests launch no process or Job and touch no runtime data. The explicit
NativeTransferSmoke.native_cross_process_duplicate selector launches one bounded
voluntary child solely to check DuplicateHandle. RPC authentication, managed
launch provenance and native post-exit membership require separate evidence.
Win32 references: https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob
"""
import ctypes as C
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import identity as identities
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess, retry_identity_cleanup


PEER = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")
ROOT = ProcessIdentity(202, 134342315823996140, PEER.logon_id)


class TransferBackend:
    """Explicit fake handle table. Wire locator 55 is never a local handle."""
    def __init__(self):
        self.identities = {100: PEER, 200: PEER, 300: ROOT, 400: PEER}
        self.states = {100: IdentityStatus.ALIVE, 200: IdentityStatus.ALIVE,
                       300: IdentityStatus.DEAD, 400: IdentityStatus.ALIVE}
        self.calls = []
        self.errors = {}
        self.duplicate_error = None
        self.write_before_error = False
        self.duplicate_hook = None
        self.check_lock = None
        self.member = True

    def record(self, *call):
        self.calls.append(call)
        if self.check_lock:
            self.check_lock()

    def open_process(self, pid):
        self.record("open", pid)
        if pid != PEER.pid:
            raise AssertionError("root PID reopened")
        return 100

    def open_transfer_source(self, pid):
        self.record("open_transfer", pid)
        return 200

    def identity(self, handle):
        self.record("identity", handle)
        value = self.identities[handle]
        if isinstance(value, BaseException):
            raise value
        return value

    def wait(self, handle):
        self.record("wait", handle)
        return self.states[handle]

    def duplicate_into(self, locator, output, *, source_process=None):
        self.record("duplicate", source_process, locator)
        if self.duplicate_error is None or self.write_before_error:
            output.value = 400 if source_process is None else 300
        if self.duplicate_hook:
            self.duplicate_hook()
        if self.duplicate_error:
            raise self.duplicate_error

    def membership(self, handle, job):
        self.record("membership", handle, job)
        if isinstance(self.member, BaseException):
            raise self.member
        return self.member

    def exit_code(self, handle):
        self.record("exit_code", handle)
        return 259

    def close(self, handle):
        self.record("close", handle)
        if handle in self.errors:
            raise self.errors[handle]


class ProcessTransferTests(unittest.TestCase):
    def setUp(self):
        self.backend = TransferBackend()
        override = patch.object(identities, "_backend", return_value=self.backend)
        override.start()
        self.addCleanup(override.stop)
        self.peer = VerifiedProcess.open(PEER)
        self.addCleanup(self.peer.close)
        self.backend.calls.clear()

    def copy_root(self):
        return self.peer.duplicate_remote_handle(55, expected=ROOT)

    def test_local_copy_outlives_borrowed_peer_scope_with_independent_handle(self):
        copied = self.peer.duplicate()
        try:
            self.peer.close()
            self.assertEqual(copied.identity, PEER)
            self.assertIs(copied.observe().status, IdentityStatus.ALIVE)
            self.assertIn(("duplicate", None, 100), self.backend.calls)
            self.assertNotIn(("close", 400), self.backend.calls)
            self.assertFalse(any(call[0] == "open" for call in self.backend.calls))
        finally:
            copied.close()
        self.assertIn(("close", 400), self.backend.calls)

    def test_local_copy_preserves_already_dead_exact_process(self):
        self.backend.states[100] = self.backend.states[400] = IdentityStatus.DEAD
        with self.peer.duplicate() as copied:
            self.assertIs(copied.observe().status, IdentityStatus.DEAD)
            self.assertEqual(copied.exit_code(), 259)
        self.assertNotIn(("wait", 100), self.backend.calls)

    def test_remote_copy_pins_live_peer_and_supports_dead_root_without_pid_reopen(self):
        with self.copy_root() as root:
            self.assertEqual(root.identity, ROOT)
            calls_before_observe = list(self.backend.calls)
            self.assertNotIn(("wait", 300), calls_before_observe)
            self.assertIn(("identity", 300), calls_before_observe)
            self.assertIn(("close", 200), calls_before_observe)
            self.assertEqual([call for call in calls_before_observe if call[0].startswith("open")],
                             [("open_transfer", PEER.pid)])
            self.assertIn(("duplicate", 200, 55), calls_before_observe)
            self.assertIs(root.observe().status, IdentityStatus.DEAD)
            self.assertEqual(root.exit_code(), 259)
        self.assertNotIn(("close", 55), self.backend.calls)
        self.assertNotIn(("close", 100), self.backend.calls)

    def test_remote_locator_expected_type_and_logon_reject_before_native_use(self):
        for locator in (None, True, 0, -1, 1 << 63, "55"):
            with self.subTest(locator=locator), self.assertRaises(ValueError):
                self.peer.duplicate_remote_handle(locator, expected=ROOT)
        with self.assertRaises(TypeError):
            self.peer.duplicate_remote_handle(55, expected=ROOT.to_dict())
        with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
            self.peer.duplicate_remote_handle(55, expected=replace(ROOT, logon_id="S-1-5-5-100-201"))
        self.assertEqual(self.backend.calls, [])

    def test_peer_pid_reuse_is_rejected_before_remote_duplicate(self):
        self.backend.identities[200] = replace(PEER, created_filetime_100ns=PEER.created_filetime_100ns + 1)
        with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
            self.copy_root()
        self.assertFalse(any(call[0] == "duplicate" for call in self.backend.calls))
        self.assertIn(("close", 200), self.backend.calls)

    def test_nonlive_or_unknown_original_peer_never_opens_source_capability(self):
        for state in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN, None):
            self.backend.states[100] = state
            self.backend.calls.clear()
            with self.subTest(state=state), self.assertRaisesRegex(
                    IdentityUnavailable, "process_transfer_source_unverified"):
                self.copy_root()
            self.assertEqual(self.backend.calls, [("wait", 100)])

    def test_closed_or_quarantined_peer_cannot_duplicate_or_query_membership(self):
        self.peer._close_outcome_unknown = True
        try:
            for operation in (self.peer.duplicate, self.copy_root):
                with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                        IdentityUnavailable, "process_handle_close_outcome_unknown"):
                    operation()
            self.assertIsNone(self.peer.query_owned_job_membership(800))
            self.assertEqual(self.backend.calls, [])
        finally:
            # The fixture models existing quarantine; no native close occurred.
            self.peer._close_outcome_unknown = False
        self.peer.close()
        self.backend.calls.clear()
        for operation in (self.peer.duplicate, self.copy_root):
            with self.subTest(operation=operation.__name__), self.assertRaisesRegex(
                    IdentityUnavailable, "identity_handle_closed"):
                operation()
        self.assertIsNone(self.peer.query_owned_job_membership(800))
        self.assertEqual(self.backend.calls, [])

    def test_peer_exit_during_duplicate_does_not_publish_root(self):
        self.backend.duplicate_hook = lambda: self.backend.states.__setitem__(100, IdentityStatus.DEAD)
        with self.assertRaisesRegex(IdentityUnavailable, "process_transfer_source_unverified"):
            self.copy_root()
        self.assertIn(("close", 300), self.backend.calls)
        self.assertIn(("close", 200), self.backend.calls)

    def test_all_root_identity_fields_are_checked_before_any_root_wait(self):
        for mismatch in (replace(ROOT, pid=203),
                         replace(ROOT, created_filetime_100ns=ROOT.created_filetime_100ns + 1),
                         replace(ROOT, logon_id="S-1-5-5-100-201")):
            with self.subTest(identity=mismatch):
                self.backend.calls.clear()
                self.backend.identities[300] = mismatch
                with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
                    self.copy_root()
                self.assertNotIn(("wait", 300), self.backend.calls)
                self.assertIn(("close", 300), self.backend.calls)
                self.assertIn(("close", 200), self.backend.calls)

    def test_nonprocess_locator_is_never_waited_on(self):
        self.backend.identities[300] = IdentityUnavailable("process_identity_unavailable", 6)
        with self.assertRaisesRegex(IdentityUnavailable, "process_identity_unavailable"):
            self.copy_root()
        self.assertNotIn(("wait", 300), self.backend.calls)
        self.assertIn(("close", 300), self.backend.calls)

    def test_peer_owner_lock_survives_acquisition_validation_and_source_cleanup(self):
        def held():
            acquired = self.peer._lock.acquire(blocking=False)
            if acquired:
                self.peer._lock.release()
            self.assertFalse(acquired)
        self.backend.check_lock = held
        root = self.copy_root()
        self.backend.check_lock = None
        root.close()

    def test_unknown_duplicate_output_is_quarantined_never_speculatively_closed(self):
        primary = OSError("synthetic duplicate interrupted")
        self.backend.duplicate_error = primary
        self.backend.write_before_error = True
        with self.assertRaises(OSError) as caught:
            self.copy_root()
        self.assertIs(caught.exception, primary)
        self.assertTrue(primary._native_duplicate_outcome_unknown)
        self.assertNotIn(("close", 300), self.backend.calls)
        self.assertIn(("close", 200), self.backend.calls)
        with self.assertRaisesRegex(IdentityUnavailable, "process_duplicate_outcome_unknown"):
            retry_identity_cleanup(primary)
        self.assertNotIn(("close", 300), self.backend.calls)

    def test_explicit_false_with_populated_output_is_also_quarantined(self):
        error = IdentityUnavailable("process_duplicate_unavailable", 6)
        error._native_duplicate_failed = True
        self.backend.duplicate_error = error
        self.backend.write_before_error = True
        with self.assertRaises(IdentityUnavailable) as caught:
            self.copy_root()
        self.assertIs(caught.exception, error)
        self.assertTrue(error._native_duplicate_outcome_unknown)
        self.assertNotIn(("close", 300), self.backend.calls)

    def test_quarantined_duplicate_does_not_block_independent_source_cleanup_retry(self):
        primary = OSError("synthetic duplicate interrupted")
        self.backend.duplicate_error = primary
        self.backend.write_before_error = True
        self.backend.errors[200] = IdentityUnavailable("process_handle_close_failed", 5)
        with self.assertRaises(OSError) as caught:
            self.copy_root()
        self.assertIs(caught.exception, primary)
        self.assertEqual(len(primary._identity_handle_cleanup), 2)
        self.assertEqual(self.backend.calls.count(("close", 200)), 1)
        self.backend.errors.clear()
        with self.assertRaisesRegex(IdentityUnavailable, "process_duplicate_outcome_unknown") as retry:
            retry_identity_cleanup(primary)
        self.assertEqual(self.backend.calls.count(("close", 200)), 2)
        self.assertNotIn(("close", 300), self.backend.calls)
        self.assertEqual(len(primary._identity_handle_cleanup), 1)
        self.assertIs(primary._identity_handle_cleanup[0], retry.exception._identity_handle_cleanup[0])
        with self.assertRaisesRegex(IdentityUnavailable, "process_duplicate_outcome_unknown"):
            retry_identity_cleanup(retry.exception)
        self.assertEqual(self.backend.calls.count(("close", 200)), 2)

    def test_publication_interruption_closes_only_the_actual_duplicate_owner(self):
        original_setattr = identities._TransferDuplicate.__setattr__
        for remote in (False, True):
            for after_retirement in (False, True):
                with self.subTest(remote=remote, after_retirement=after_retirement):
                    handle = 300 if remote else 400
                    primary = KeyboardInterrupt("synthetic publication interrupted")
                    fired = False
                    self.backend.calls.clear()

                    def interrupt_retirement(owner, name, value):
                        nonlocal fired
                        if (not fired and name == "_handle" and value is None
                                and getattr(owner, "_handle", None) == handle):
                            fired = True
                            if after_retirement:
                                original_setattr(owner, name, value)
                            raise primary
                        original_setattr(owner, name, value)

                    with patch.object(identities._TransferDuplicate, "__setattr__", interrupt_retirement):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            self.copy_root() if remote else self.peer.duplicate()
                    self.assertIs(caught.exception, primary)
                    self.assertTrue(fired)
                    self.assertEqual(self.backend.calls.count(("close", handle)), 1)
                    self.assertEqual(self.backend.calls.count(("close", 200)), int(remote))
                    self.assertNotIn(("close", 100), self.backend.calls)
                    self.assertFalse(getattr(primary, "_identity_handle_cleanup", ()))

    def test_publication_interruption_and_failed_close_retain_the_actual_owner(self):
        original_setattr = identities._TransferDuplicate.__setattr__
        for remote in (False, True):
            for after_retirement in (False, True):
                with self.subTest(remote=remote, after_retirement=after_retirement):
                    handle = 300 if remote else 400
                    primary = KeyboardInterrupt("synthetic publication interrupted")
                    fired = False
                    self.backend.calls.clear()
                    self.backend.errors[handle] = IdentityUnavailable("process_handle_close_failed", 5)

                    def interrupt_retirement(owner, name, value):
                        nonlocal fired
                        if (not fired and name == "_handle" and value is None
                                and getattr(owner, "_handle", None) == handle):
                            fired = True
                            if after_retirement:
                                original_setattr(owner, name, value)
                            raise primary
                        original_setattr(owner, name, value)

                    with patch.object(identities._TransferDuplicate, "__setattr__", interrupt_retirement):
                        with self.assertRaises(KeyboardInterrupt) as caught:
                            self.copy_root() if remote else self.peer.duplicate()
                    self.assertIs(caught.exception, primary)
                    self.assertEqual(self.backend.calls.count(("close", handle)), 1)
                    self.assertEqual(len(primary._identity_handle_cleanup), 1)
                    owner = primary._identity_handle_cleanup[0]
                    self.assertEqual(owner._handle, handle)
                    self.assertIs(isinstance(owner, VerifiedProcess), after_retirement)
                    self.backend.errors.clear()
                    retry_identity_cleanup(primary)
                    self.assertEqual(self.backend.calls.count(("close", handle)), 2)
                    self.assertEqual(primary._identity_handle_cleanup, ())

    def test_explicit_false_with_empty_output_closes_only_source_authority(self):
        error = IdentityUnavailable("process_duplicate_unavailable", 6)
        error._native_duplicate_failed = True
        self.backend.duplicate_error = error
        with self.assertRaises(IdentityUnavailable) as caught:
            self.copy_root()
        self.assertIs(caught.exception, error)
        self.assertFalse(getattr(error, "_native_duplicate_outcome_unknown", False))
        self.assertFalse(getattr(error, "_identity_handle_cleanup", ()))
        self.assertEqual([call for call in self.backend.calls if call[0] == "close"], [("close", 200)])

    def test_identity_failure_retains_both_failed_cleanup_owners_and_primary(self):
        primary = IdentityUnavailable("synthetic root identity failure")
        self.backend.identities[300] = primary
        self.backend.errors = {handle: IdentityUnavailable("process_handle_close_failed", 5)
                               for handle in (200, 300)}
        with self.assertRaises(IdentityUnavailable) as caught:
            self.copy_root()
        self.assertIs(caught.exception, primary)
        self.assertEqual({owner._handle for owner in primary._identity_handle_cleanup}, {200, 300})
        self.backend.errors.clear()
        retry_identity_cleanup(primary)
        self.assertEqual(primary._identity_handle_cleanup, ())
        self.assertEqual([call for call in self.backend.calls if call == ("close", 200)], [("close", 200)] * 2)

    def test_temporary_source_close_failure_cannot_publish_success_or_retry_close_inline(self):
        primary = IdentityUnavailable("process_handle_close_failed", 5)
        self.backend.errors[200] = primary
        with self.assertRaises(IdentityUnavailable) as caught:
            self.copy_root()
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.backend.calls.count(("close", 200)), 1)
        self.assertIn(("close", 300), self.backend.calls)
        self.assertEqual(len(primary._identity_handle_cleanup), 1)
        self.backend.errors.clear()
        retry_identity_cleanup(primary)

    def test_dead_membership_queries_native_result_without_wait_or_pid_reopen(self):
        with self.copy_root() as root:
            for value, expected in ((True, True), (False, False), (None, None),
                                    (1, None), (IdentityUnavailable("membership_unknown", 5), None)):
                with self.subTest(value=repr(value)):
                    self.backend.member = value
                    self.backend.calls.clear()
                    self.assertIs(root.query_owned_job_membership(800), expected)
                    self.assertEqual(self.backend.calls, [("membership", 300, 800)])

    def test_owned_membership_invalid_job_and_closed_handle_make_no_native_queries(self):
        root = self.copy_root()
        for job in (None, True, 0, -1, 1 << 63):
            with self.subTest(job=job), self.assertRaises(ValueError):
                root.query_owned_job_membership(job)
        root.close()
        self.backend.calls.clear()
        self.assertIsNone(root.query_owned_job_membership(800))
        self.assertEqual(self.backend.calls, [])


class TransferWin32BindingTests(unittest.TestCase):
    def test_source_capability_and_duplicate_rights_are_narrow_and_noninheritable(self):
        calls = []
        def open_process(access, inherit, pid):
            calls.append(("open", access, inherit, pid))
            return 200
        def duplicate(source, locator, target, output, access, inherit, options):
            calls.append(("duplicate", source, locator, target, access, inherit, options))
            C.cast(output, C.POINTER(identities._HANDLE)).contents.value = 300
            return 1
        backend = identities._WindowsBackend.__new__(identities._WindowsBackend)
        backend.kernel = SimpleNamespace(OpenProcess=open_process, GetCurrentProcess=lambda: -1,
                                         DuplicateHandle=duplicate)
        self.assertEqual(backend.open_transfer_source(PEER.pid), 200)
        output = identities._HANDLE()
        backend.duplicate_into(55, output, source_process=200)
        self.assertEqual(output.value, 300)
        self.assertEqual(calls, [("open", 0x1000 | 0x100000 | 0x40, False, PEER.pid),
                                ("duplicate", 200, 55, -1, 0x1000 | 0x100000, False, 0)])
        self.assertEqual(identities._PROCESS_ACCESS, 0x1000 | 0x100000)

    def test_backend_false_marks_only_known_failure_for_output_owner(self):
        backend = identities._WindowsBackend.__new__(identities._WindowsBackend)
        backend.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1, DuplicateHandle=lambda *args: 0)
        with patch.object(identities.C, "get_last_error", create=True, return_value=6):
            with self.assertRaises(IdentityUnavailable) as caught:
                backend.duplicate_into(55, identities._HANDLE(), source_process=200)
        self.assertTrue(caught.exception._native_duplicate_failed)
        self.assertEqual(caught.exception.win32_error, 6)


# Retain failed fixtures, exceptions and all still-owned handles. A later explicit
# invocation in this interpreter may not discard uncertainty and launch again.
_NATIVE_TRANSFER_SMOKE_RETAINED = []


def _transfer_child(directory):
    """One-thread fixture: no blocking stdin read, no background exit thread."""
    import msvcrt

    directory = Path(directory)
    until = time.monotonic() + 12
    result = {"ok": False, "own_handle_closed": False}
    current = None
    try:
        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.PeekNamedPipe.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32,
            C.POINTER(C.c_uint32), C.POINTER(C.c_uint32), C.POINTER(C.c_uint32)]
        kernel.PeekNamedPipe.restype = C.c_int32
        stdin_handle = msvcrt.get_osfhandle(sys.stdin.fileno())
        current = VerifiedProcess.current()
        temporary = directory / "transfer-bootstrap.tmp"
        temporary.write_text(json.dumps({"identity": current.identity.to_dict(),
            "locator": current._handle}), encoding="utf-8")
        temporary.replace(directory / "transfer-bootstrap.json")
        # PeekNamedPipe returns immediately for a single-threaded caller, even
        # on an empty anonymous pipe. Never perform a blocking read or depend on
        # a parent's willingness to send data for this child to exit.
        # https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-peeknamedpipe
        while time.monotonic() < until:
            available = C.c_uint32()
            if not kernel.PeekNamedPipe(stdin_handle, None, 0, None, C.byref(available), None):
                if C.get_last_error() == 109:  # ERROR_BROKEN_PIPE: voluntary EOF
                    result.update(ok=True, stopped_by="stdin_closed")
                    break
                raise IdentityUnavailable("transfer_child_stdin_unavailable", C.get_last_error())
            if available.value:
                result.update(ok=True, stopped_by="stdin_signal")
                break
            time.sleep(.02)
        else:
            result["reason"] = "transfer_child_timer_expired"
    except BaseException as error:
        result.update(error_type=type(error).__name__, reason=getattr(error, "reason", None))
    finally:
        if current is not None:
            try:
                current.close()
                result["own_handle_closed"] = current._handle is None and not current._close_outcome_unknown
            except BaseException as error:
                result.update(ok=False, cleanup_error_type=type(error).__name__,
                              cleanup_reason=getattr(error, "reason", None))
        (directory / "transfer-child-result.json").write_text(json.dumps(result), encoding="utf-8")
    return 0 if result["ok"] and result["own_handle_closed"] else 1


@unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8,
                     "explicit real cross-process transfer requires Windows x64")
class NativeTransferSmoke(unittest.TestCase):
    def native_cross_process_duplicate(self):
        """Explicit primitive ABI evidence only; no Job, control or P1 pass.

        The private test handshake is checked against the Popen child PID and
        then full retained native identity. It is not production IPC peer proof.
        The child has its own 12-second timer; parent cleanup never kills it.
        """
        if _NATIVE_TRANSFER_SMOKE_RETAINED:
            self.fail("previous native transfer fixture unresolved; no further launch")
        directory = Path(tempfile.mkdtemp(prefix="sentinel-native-transfer-"))
        entry = {"directory": str(directory), "child": None, "owners": [], "errors": []}
        _NATIVE_TRANSFER_SMOKE_RETAINED.append(entry)
        deadline = time.monotonic() + 18
        primary = None
        cleanup_errors = []
        evidence = {"operation": "cross_process_duplicate", "job_created": False,
                    "control_writes": False, "child_exit_verified": False,
                    "parent_handles_closed": False, "passed": False}
        child = None
        try:
            child = subprocess.Popen([sys.executable, "-m", "tests.test_adaptive_identity_transfer",
                "--transfer-child", str(directory)], cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            entry["child"] = child
            bootstrap = directory / "transfer-bootstrap.json"
            bootstrap_until = min(deadline, time.monotonic() + 8)
            while not bootstrap.is_file() and child.poll() is None and time.monotonic() < bootstrap_until:
                time.sleep(.01)
            self.assertTrue(bootstrap.is_file(), "bounded transfer child bootstrap unavailable")
            info = json.loads(bootstrap.read_text(encoding="utf-8"))
            expected = ProcessIdentity.from_dict(info["identity"])
            self.assertEqual(expected.pid, child.pid)
            self.assertNotEqual(expected.pid, os.getpid())
            peer = VerifiedProcess.open(expected)
            entry["owners"].append(peer)
            self.assertIs(peer.observe().status, IdentityStatus.ALIVE)
            copied = peer.duplicate_remote_handle(info["locator"], expected=expected)
            entry["owners"].append(copied)
            independent = peer.duplicate()
            entry["owners"].append(independent)
            self.assertEqual(len({peer._handle, copied._handle, independent._handle}), 3)
            peer.close()
            for owner in (copied, independent):
                self.assertEqual(owner.identity, expected)
                self.assertEqual(owner._backend.identity(owner._handle), expected)
                self.assertIs(owner.observe().status, IdentityStatus.ALIVE)
            child.stdin.close()
            self.assertEqual(child.wait(timeout=max(.01, deadline - time.monotonic())), 0)
            evidence["child_exit_verified"] = True
            for owner in (copied, independent):
                self.assertIs(owner.observe().status, IdentityStatus.DEAD)
                self.assertEqual(owner.exit_code(), 0)
            result = json.loads((directory / "transfer-child-result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["ok"], result)
            self.assertTrue(result["own_handle_closed"], result)
            self.assertEqual(result["stopped_by"], "stdin_closed")
            evidence["passed"] = True
        except BaseException as error:
            primary = error
            entry["errors"].append(error)
            for owner in getattr(error, "_identity_handle_cleanup", ()):
                if owner not in entry["owners"]:
                    entry["owners"].append(owner)
            evidence.update(error_type=type(error).__name__, reason=getattr(error, "reason", None))
            raise
        finally:
            # Independent cleanup preserves the initial failure. Already failed
            # closes stay attached for explicit recovery, never inline retries.
            failed_owners = getattr(primary, "_identity_handle_cleanup", ())
            for owner in reversed(entry["owners"]):
                if any(owner is pending for pending in failed_owners):
                    cleanup_errors.append(primary)
                    continue
                try:
                    owner.close()
                    if owner._handle is not None or owner._close_outcome_unknown:
                        raise AssertionError("native transfer owner cleanup unverified")
                except BaseException as error:
                    cleanup_errors.append(error)
                    entry["errors"].append(error)
            if child is not None:
                try:
                    if child.stdin is not None and not child.stdin.closed:
                        child.stdin.close()
                except BaseException as error:
                    cleanup_errors.append(error)
                    entry["errors"].append(error)
                # A stream-close failure cannot skip observing this same child.
                # All attempts share the original absolute deadline; timeout
                # retains the Popen handle and never permits kill or relaunch.
                try:
                    child.wait(timeout=max(.01, deadline - time.monotonic()))
                    evidence["child_exit_verified"] = True
                except BaseException as error:
                    cleanup_errors.append(error)
                    entry["errors"].append(error)
                else:
                    try:
                        # Popen.wait does not retire its Windows process handle.
                        child._handle.Close()
                    except BaseException as error:
                        cleanup_errors.append(error)
                        entry["errors"].append(error)
            evidence["parent_handles_closed"] = not cleanup_errors
            evidence["passed"] = evidence["passed"] and not cleanup_errors
            evidence["cleanup_error_types"] = [type(error).__name__ for error in cleanup_errors]
            evidence_path = directory / "transfer-smoke-result.json"
            try:
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
            except BaseException as error:
                cleanup_errors.append(error)
                entry["errors"].append(error)
            if primary is not None:
                primary.add_note("native transfer evidence retained at " + str(directory))
                if cleanup_errors:
                    primary.add_note("native_transfer_cleanup_unverified_custody_retained")
            elif cleanup_errors:
                cleanup_errors[0].add_note("native transfer evidence retained at " + str(directory))
                raise cleanup_errors[0]
            else:
                _NATIVE_TRANSFER_SMOKE_RETAINED.remove(entry)
                print("native_transfer_smoke_evidence=" + str(evidence_path))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--transfer-child":
        raise SystemExit(_transfer_child(sys.argv[2]))
    unittest.main()
