"""Portable mutex state tests and separately selectable native Windows tests.

Native cases use fresh UUID names, short test threads/processes and no Jobs,
workload controls, runtime files or Scheduled Tasks. They prove mutex behavior
only, not native lifecycle/launch/recovery readiness. Contender processes have
a self-deadline; the parent never kills a process on an observation timeout.
"""
from dataclasses import FrozenInstanceError, replace
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive import windows as native
from sentinel.adaptive.windows import NativePolicyMutex, NativePolicyMutexError


LOGON = "S-1-5-5-100-200"
OWNER = "S-1-5-21-100-200-300-1001"


class FixtureProcess:
    def __init__(self):
        self.identity = ProcessIdentity(os.getpid(), 134342315823996135, LOGON)
        self.status = IdentityStatus.ALIVE
        self.closed = 0
        self.close_error = None

    def observe(self):
        return SimpleNamespace(identity=self.identity, status=self.status)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error
        return False


class FixtureBackend:
    def __init__(self):
        self.calls = []
        self.next_handle = 700
        self.wait_result = False
        self.wait_error = self.release_error = self.close_error = None
        self.wait_callback = None

    def current_owner_sid(self):
        self.calls.append(("owner",))
        return OWNER

    def create(self, name, logon, owner):
        self.next_handle += 1
        self.calls.append(("create", self.next_handle, name, logon, owner))
        return self.next_handle

    def wait(self, handle, timeout_ms):
        self.calls.append(("wait", handle, timeout_ms))
        if self.wait_callback is not None:
            return self.wait_callback(handle, timeout_ms)
        if self.wait_error is not None:
            raise self.wait_error
        return self.wait_result

    def release(self, handle):
        self.calls.append(("release", handle))
        if self.release_error is not None:
            raise self.release_error

    def close(self, handle):
        self.calls.append(("close", handle))
        if self.close_error is not None:
            raise self.close_error


class PolicyMutexTests(unittest.TestCase):
    def setUp(self):
        self.backend = FixtureBackend()
        self.process = FixtureProcess()
        backend_patch = patch.object(native, "_backend", return_value=self.backend)
        identity_patch = patch.object(native.VerifiedProcess, "current", return_value=self.process)
        backend_patch.start()
        self.current = identity_patch.start()
        self.addCleanup(backend_patch.stop)
        self.addCleanup(identity_patch.stop)

    def mutex(self, instance=None):
        mutex = NativePolicyMutex(LOGON, instance or str(uuid4()))
        self.addCleanup(self.cleanup_fixture_mutex, mutex)
        return mutex

    def cleanup_fixture_mutex(self, mutex):
        # Quarantined fake handles have no OS ownership. Remove only this
        # fixture's unique name, never reset the global native registry.
        self.assertIs(mutex._api, self.backend)
        with native._THREAD_NAMES_LOCK:
            native._THREAD_NAMES.difference_update(
                key for key in tuple(native._THREAD_NAMES) if key[1] == mutex.name)
        mutex._owner = mutex._owner_native_id = None
        mutex._waiting = False
        self.backend.close_error = None
        mutex.close()

    def assert_reason(self, reason, operation):
        with self.assertRaises(NativePolicyMutexError) as caught:
            operation()
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(str(caught.exception), reason)
        return caught.exception

    def test_invalid_logon_and_instance_rejected_before_native_identity(self):
        for logon in (None, 12, "S-1-5-21-100", LOGON + "\n", "S-1-5-5-4294967296-1"):
            with self.subTest(logon=logon):
                self.assert_reason("policy_mutex_logon_invalid",
                                   lambda: NativePolicyMutex(logon, str(uuid4())))
        canonical = "12345678-abcd-4abc-8abc-123456789abc"
        for instance in (None, 12, "bad", "0" * 32, canonical.upper(), canonical.replace("-", "")):
            with self.subTest(instance=instance):
                self.assert_reason("policy_mutex_instance_invalid",
                                   lambda: NativePolicyMutex(LOGON, instance))
        self.current.assert_not_called()
        self.assertEqual(self.backend.calls, [])

    def test_current_exact_pid_logon_and_alive_are_required_before_create(self):
        original = self.process.identity
        for identity, status in (
            (replace(original, pid=original.pid + 1), IdentityStatus.ALIVE),
            (replace(original, logon_id="S-1-5-5-100-201"), IdentityStatus.ALIVE),
            (original, IdentityStatus.UNKNOWN), (original, IdentityStatus.DEAD),
        ):
            with self.subTest(identity=identity, status=status):
                self.process.identity, self.process.status = identity, status
                self.assert_reason("policy_mutex_current_logon_mismatch", self.mutex)
        self.assertEqual(self.backend.calls, [])
        self.assertEqual(self.process.closed, 4)

    def test_identity_unavailable_has_only_stable_reason_and_numeric_code(self):
        self.current.side_effect = IdentityUnavailable("private diagnostic", 5)
        error = self.assert_reason("policy_mutex_identity_unavailable", self.mutex)
        self.assertEqual(error.win32_error, 5)
        self.assertTrue(error.__suppress_context__)
        self.assertEqual(self.backend.calls, [])

    def test_name_frozen_lease_and_retained_handle_release_before_close(self):
        mutex = self.mutex()
        handle = mutex._handle
        self.assertEqual(mutex.name, f"Local\\ResourceSentinel.Policy.{LOGON}.{mutex.instance_id}")
        self.assertEqual(self.process.closed, 1)
        with mutex as retained:
            self.assertIs(retained, mutex)
            with mutex.acquire(0) as lease:
                self.assertEqual((lease.name, lease.instance_id, lease.logon_id, lease.abandoned),
                                 (mutex.name, mutex.instance_id, LOGON, False))
                self.assertEqual(mutex._handle, handle)
                self.assertNotIn(("close", handle), self.backend.calls)
                with self.assertRaises(FrozenInstanceError):
                    lease.abandoned = True
            self.assertEqual(mutex._handle, handle)
        mutex.close()
        self.assertIsNone(mutex._handle)
        self.assertEqual(self.backend.calls[-3:], [("wait", handle, 0), ("release", handle), ("close", handle)])
        self.assertEqual(self.backend.calls.count(("close", handle)), 1)
        for field in ("name", "instance_id", "logon_id"):
            with self.assertRaises(AttributeError):
                setattr(mutex, field, "changed")
        self.assert_reason("policy_mutex_closed", lambda: mutex._wait(0))

    def test_timeout_validation_and_known_wait_failure_allow_fresh_attempt(self):
        mutex = self.mutex()
        for timeout in (-1, 5001, True, 1.0, None):
            self.assert_reason("policy_mutex_timeout_invalid", lambda: mutex._wait(timeout))
        self.assertFalse(any(call[0] == "wait" for call in self.backend.calls))
        for reason in ("policy_mutex_timeout", "policy_mutex_wait_failed"):
            self.backend.wait_error = NativePolicyMutexError(reason, 5)
            self.assert_reason(reason, lambda: mutex._wait(5000))
            self.assertFalse(mutex._waiting)
            self.assertIsNone(mutex._owner)
            self.assertNotIn((threading.current_thread(), mutex.name), native._THREAD_NAMES)
            self.backend.wait_error = None
            with mutex.acquire(0):
                pass

    def test_same_object_and_same_name_recursion_rejected_before_second_wait(self):
        first = self.mutex()
        same = self.mutex(first.instance_id)
        different = self.mutex()
        with first.acquire():
            self.assert_reason("policy_mutex_recursive_entry", lambda: first._wait(0))
            self.assert_reason("policy_mutex_recursive_entry", lambda: same._wait(0))
            with different.acquire():
                pass
        with same.acquire():
            pass
        self.assertEqual(sum(call[0] == "wait" for call in self.backend.calls), 3)

    def test_other_thread_cannot_release_acquire_or_close_owned_instance(self):
        mutex = self.mutex()
        results = []
        def contender():
            for operation in (mutex._release, lambda: mutex._wait(0), mutex.close):
                try:
                    operation()
                except NativePolicyMutexError as error:
                    results.append(error.reason)
        with mutex.acquire():
            thread = threading.Thread(target=contender, daemon=True)
            thread.start()
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, ["policy_mutex_not_owner_thread", "policy_mutex_busy", "policy_mutex_busy"])
        self.assertIsNone(mutex._owner)

    def test_native_thread_id_must_also_match_to_release(self):
        mutex = self.mutex()
        with mutex.acquire():
            with patch.object(native.threading, "get_native_id", return_value=mutex._owner_native_id + 1):
                self.assert_reason("policy_mutex_not_owner_thread", mutex._release)
            self.assertIs(mutex._owner, threading.current_thread())

    def test_waiting_handle_cannot_close_and_scope_releases_on_same_thread(self):
        mutex = self.mutex()
        waiting, proceed = threading.Event(), threading.Event()
        errors = []
        def wait(handle, timeout):
            waiting.set()
            if not proceed.wait(3):
                raise NativePolicyMutexError("policy_mutex_timeout")
            return False
        def owner():
            try:
                with mutex.acquire(250):
                    pass
            except BaseException as error:
                errors.append(error)
        self.backend.wait_callback = wait
        thread = threading.Thread(target=owner, daemon=True)
        thread.start()
        try:
            self.assertTrue(waiting.wait(3))
            self.assert_reason("policy_mutex_busy", mutex.close)
            self.assert_reason("policy_mutex_busy", lambda: mutex._wait(0))
        finally:
            proceed.set()
            thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertIsNone(mutex._owner)
        self.assertFalse(mutex._waiting)

    def test_unknown_wait_outcomes_quarantine_without_release_or_close(self):
        for result, error in ((None, KeyboardInterrupt()), (1, None),
                              (None, NativePolicyMutexError("policy_mutex_wait_invalid"))):
            with self.subTest(result=result, error=type(error).__name__):
                mutex = self.mutex()
                self.backend.wait_result, self.backend.wait_error = result, error
                with self.assertRaises(BaseException) as caught:
                    mutex._wait(0)
                if error is not None:
                    self.assertIs(caught.exception, error)
                self.assertIn("policy_mutex_wait_outcome_unknown", caught.exception.__notes__)
                self.assertTrue(mutex._waiting)
                self.assert_reason("policy_mutex_busy", mutex.close)
                self.assert_reason("policy_mutex_busy", lambda: mutex._wait(0))
                self.assertNotIn(("release", mutex._handle), self.backend.calls)
                self.assertNotIn(("close", mutex._handle), self.backend.calls)

    def test_release_failure_retains_owner_and_can_be_retried_by_exact_owner(self):
        mutex = self.mutex()
        failure = NativePolicyMutexError("policy_mutex_release_failed", 288)
        self.backend.release_error = failure
        with self.assertRaises(NativePolicyMutexError) as caught:
            with mutex.acquire():
                pass
        self.assertIs(caught.exception, failure)
        self.assertIs(mutex._owner, threading.current_thread())
        self.assert_reason("policy_mutex_busy", mutex.close)
        self.assert_reason("policy_mutex_recursive_entry", lambda: mutex._wait(0))
        self.backend.release_error = None
        mutex._release()
        self.assertIsNone(mutex._owner)
        self.assertNotIn((threading.current_thread(), mutex.name), native._THREAD_NAMES)

    def test_body_failure_survives_release_and_close_failures_with_sanitized_notes(self):
        mutex = self.mutex()
        primary = ValueError("body failure")
        self.backend.release_error = NativePolicyMutexError("sensitive cleanup payload", 288)
        with self.assertRaises(ValueError) as caught:
            with mutex:
                with mutex.acquire():
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, ["policy_mutex_release_failed win32=288", "policy_mutex_handle_close_failed"])
        self.assertNotIn("sensitive", " ".join(primary.__notes__))
        self.assertIs(mutex._owner, threading.current_thread())
        self.backend.release_error = None
        mutex._release()
        mutex.close()

    def test_handle_close_failure_keeps_handle_and_preserves_body_exception(self):
        mutex = self.mutex()
        handle = mutex._handle
        failure = NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        self.backend.close_error = failure
        with self.assertRaises(NativePolicyMutexError) as caught:
            with mutex:
                pass
        self.assertIs(caught.exception, failure)
        self.assertEqual(mutex._handle, handle)
        primary = LookupError("body")
        with self.assertRaises(LookupError) as caught:
            with mutex:
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(primary.__notes__, ["policy_mutex_handle_close_failed win32=6"])

    def test_constructor_closes_new_handle_when_identity_scope_cleanup_fails(self):
        failure = RuntimeError("identity cleanup failed")
        self.process.close_error = failure
        with self.assertRaises(RuntimeError) as caught:
            self.mutex()
        self.assertIs(caught.exception, failure)
        handle = next(call[1] for call in self.backend.calls if call[0] == "create")
        self.assertEqual(self.backend.calls[-1], ("close", handle))
        self.assertEqual(self.backend.calls.count(("close", handle)), 1)

    def test_foreign_process_cannot_use_or_close_retained_handle(self):
        mutex = self.mutex()
        with patch.object(native.os, "getpid", return_value=mutex._creator_pid + 1):
            for operation in (mutex.__enter__, lambda: mutex._wait(0), mutex.close):
                self.assert_reason("policy_mutex_foreign_process", operation)
        self.assertFalse(any(call[0] in {"wait", "close"} for call in self.backend.calls))


def _contender(logon_id, instance_id):
    # Only this test child can trigger its own watchdog. This is never a parent
    # timeout/kill path, and no managed workload or Job exists in the child.
    deadline = threading.Timer(10, lambda: os._exit(124))
    deadline.daemon = True
    deadline.start()
    try:
        with VerifiedProcess.current() as process:
            identity = process.identity
            if identity.pid != os.getpid() or identity.logon_id != logon_id or process.observe().status is not IdentityStatus.ALIVE:
                raise RuntimeError("contender_current_identity_mismatch")
        outcome = None
        with NativePolicyMutex(logon_id, instance_id) as mutex:
            try:
                with mutex.acquire(250) as lease:
                    outcome = "abandoned" if lease.abandoned else "acquired"
            except NativePolicyMutexError as error:
                if error.reason != "policy_mutex_timeout":
                    raise
                outcome = "timeout"
            released = mutex._owner is None and not mutex._waiting
        print(json.dumps({"outcome": outcome, "identity": identity.to_dict(),
                          "released": released, "closed": mutex._handle is None}), flush=True)
        return 0
    finally:
        deadline.cancel()


@unittest.skipUnless(os.name == "nt", "native Windows mutex capability is unverified on this platform")
class NativePolicyMutexTests(unittest.TestCase):
    def setUp(self):
        with VerifiedProcess.current() as process:
            self.identity = process.identity
            self.assertEqual(self.identity.pid, os.getpid())
            self.assertIs(process.observe().status, IdentityStatus.ALIVE)
            self.assertEqual(ProcessIdentity.from_dict(self.identity.to_dict()), self.identity)
        self.logon = self.identity.logon_id
        self.instance = str(uuid4())

    def assert_idle_and_close(self, mutex):
        self.assertIsNone(mutex._owner)
        self.assertFalse(mutex._waiting)
        self.assertFalse(any(key[1] == mutex.name for key in native._THREAD_NAMES))
        mutex.close()
        self.assertIsNone(mutex._handle)

    def test_exact_current_logon_security_readback_and_reopened_handle(self):
        backend = native._backend()
        owner = backend.current_owner_sid()
        with NativePolicyMutex(self.logon, self.instance) as first:
            handle = first._handle
            backend.verify_security(handle, self.logon, owner)
            with NativePolicyMutex(self.logon, self.instance) as second:
                self.assertNotEqual(first._handle, second._handle)
                self.assertEqual(first.name, second.name)
                backend.verify_security(second._handle, self.logon, owner)
                with first.acquire(0) as lease:
                    self.assertFalse(lease.abandoned)
                    self.assertEqual(first._handle, handle)
                with second.acquire(0) as lease:
                    self.assertFalse(lease.abandoned)
                self.assert_idle_and_close(second)
            self.assertEqual(first._handle, handle)
            with first.acquire(0) as lease:
                self.assertFalse(lease.abandoned)
            self.assert_idle_and_close(first)

    def child_contend(self):
        command = [sys.executable, "-X", "utf8", "-m", "tests.test_adaptive_policy_mutex",
                   "--contender", self.logon, self.instance]
        child = subprocess.Popen(command, cwd=Path(__file__).resolve().parents[1],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            stdout, stderr = child.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            # No kill/terminate/relaunch. The child owns its 10-second deadline;
            # an unresolved observation is a failure, never release evidence.
            self.fail(f"bounded mutex contender observation timed out; pid={child.pid}; exit={child.poll()}")
        self.assertEqual(child.returncode, 0, f"contender exit={child.returncode}; stderr={stderr[-2000:]}")
        self.assertIsNotNone(child.poll())
        result = json.loads(stdout)
        observed = ProcessIdentity.from_dict(result["identity"])
        self.assertEqual(observed.pid, child.pid)
        self.assertEqual(observed.logon_id, self.logon)
        self.assertTrue(result["released"])
        self.assertTrue(result["closed"])
        return result["outcome"]

    def test_cross_process_contention_times_out_then_acquires_after_release(self):
        with NativePolicyMutex(self.logon, self.instance) as mutex:
            with mutex.acquire(0):
                self.assertEqual(self.child_contend(), "timeout")
            self.assertEqual(self.child_contend(), "acquired")
            self.assert_idle_and_close(mutex)

    def test_owner_thread_exit_is_abandoned_while_process_remains_alive(self):
        backend = native._backend()
        results, errors = [], []
        with NativePolicyMutex(self.logon, self.instance) as mutex:
            raw = backend.create(mutex.name, self.logon, backend.current_owner_sid())
            def abandon():
                try:
                    results.append(backend.wait(raw, 250))
                    # Deliberately no ReleaseMutex: only this isolated owning
                    # thread exits. The process and both handles remain alive.
                except BaseException as error:
                    errors.append(error)
            thread = threading.Thread(target=abandon, daemon=True)
            thread.start()
            thread.join(5)
            if thread.is_alive():
                # Closing a still-waiting handle would be undefined. Leave it
                # intact on this failure; the native wait itself is bounded.
                self.fail("isolated abandoning thread did not finish its bounded wait")
            try:
                self.assertEqual(errors, [])
                self.assertEqual(results, [False])
                with VerifiedProcess.current() as current:
                    self.assertEqual(current.identity, self.identity)
                    self.assertIs(current.observe().status, IdentityStatus.ALIVE)
                with mutex.acquire(250) as lease:
                    self.assertTrue(lease.abandoned)
                with mutex.acquire(0) as lease:
                    self.assertFalse(lease.abandoned)
                self.assert_idle_and_close(mutex)
            finally:
                backend.close(raw)

    def test_existing_same_name_with_broader_acl_is_rejected(self):
        backend = native._backend()
        owner = backend.current_owner_sid()
        name = f"Local\\ResourceSentinel.Policy.{self.logon}.{self.instance}"
        descriptor = C.c_void_p()
        sddl = f"O:{owner}D:P(A;;0x001f0001;;;{self.logon})"
        self.assertTrue(backend.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, C.byref(descriptor), None))
        raw = None
        try:
            attributes = native._SecurityAttributes(C.sizeof(native._SecurityAttributes), descriptor, False)
            raw = backend.kernel.CreateMutexExW(C.byref(attributes), name, 0, native._ACCESS)
            self.assertTrue(raw)
            create_mutex = backend.kernel.CreateMutexExW
            rejected_handles = []
            def record_create(*args):
                handle = create_mutex(*args)
                rejected_handles.append(handle)
                return handle
            with patch.object(backend.kernel, "CreateMutexExW", side_effect=record_create):
                with patch.object(backend, "close", wraps=backend.close) as close:
                    for attempt in range(2):
                        before = len(close.call_args_list)
                        with self.assertRaises(NativePolicyMutexError) as caught:
                            NativePolicyMutex(self.logon, self.instance)
                        self.assertEqual(caught.exception.reason, "policy_mutex_dacl_mismatch")
                        self.assertEqual(len(rejected_handles), attempt + 1)
                        rejected = rejected_handles[-1]
                        self.assertTrue(rejected)
                        self.assertNotEqual(rejected, raw)
                        # Token cleanup passes a c_void_p; CreateMutexExW
                        # returns an integer handle. Verify this attempt's
                        # exact rejected handle, even if Windows later reuses
                        # its numeric value for the next opening.
                        mutex_closes = [call.args[0] for call in close.call_args_list[before:]
                                        if type(call.args[0]) is int]
                        self.assertEqual(mutex_closes, [rejected])
            abandoned = backend.wait(raw, 0)
            try:
                self.assertFalse(abandoned)
            finally:
                backend.release(raw)
        finally:
            if raw:
                backend.close(raw)
            backend.free(descriptor)

    def test_valid_but_other_logon_rejected_using_actual_current_identity(self):
        parts = self.logon.split("-")
        parts[-1] = str((int(parts[-1]) + 1) % (2 ** 32))
        with self.assertRaises(NativePolicyMutexError) as caught:
            NativePolicyMutex("-".join(parts), self.instance)
        self.assertEqual(caught.exception.reason, "policy_mutex_current_logon_mismatch")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--contender":
        raise SystemExit(_contender(sys.argv[2], sys.argv[3]))
    unittest.main()
