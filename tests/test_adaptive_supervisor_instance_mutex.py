"""Portable lifetime-owner regressions with explicit synthetic native backends.

These exercise real ownership registries and the ordinary SupervisorStartup
default. They do not establish native Windows exclusion or recovery readiness.
"""
from dataclasses import replace
import os
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import windows as native
from sentinel.adaptive.experiment_host_transport import ExperimentChildError, _no_mutex
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.supervisor_startup import SupervisorStartup, supervisor_instance_binding
from tests.test_adaptive_policy_mutex import FixtureBackend, FixtureProcess, LOGON, OWNER
from tests import test_adaptive_supervisor_startup as startup_fixture


class SupervisorInstanceMutexTests(unittest.TestCase):
    def setUp(self):
        self.backend, self.process = FixtureBackend(), FixtureProcess()
        backend_patch = patch.object(native, "_backend", return_value=self.backend)
        current_patch = patch.object(native.VerifiedProcess, "current", return_value=self.process)
        backend_patch.start()
        current_patch.start()
        self.addCleanup(backend_patch.stop)
        self.addCleanup(current_patch.stop)
        self.binding = PolicyBinding(str(uuid4()), LOGON)

    def mutex(self, *, binding=None, policy=False):
        binding = self.binding if binding is None else binding
        result = (native.NativePolicyMutex(binding.logon_id, binding.instance_id) if policy else
                  native.NativeSupervisorInstanceMutex(binding))
        self.addCleanup(self.cleanup_fixture, result)
        return result

    def cleanup_fixture(self, mutex):
        # These handles are exclusively this fixture backend's synthetic values.
        # Remove only this fixture name; never clear another test's ownership.
        self.assertIs(mutex._api, self.backend)
        with native._THREAD_NAMES_LOCK:
            for names in (native._THREAD_NAMES, native._SUPERVISOR_THREAD_NAMES):
                names.difference_update(key for key in tuple(names) if key[1] == mutex.name)
        mutex._owner = mutex._owner_native_id = None
        mutex._waiting = False
        self.backend.close_error = None
        mutex.close()

    def test_exact_derived_kernel_name_and_security_inputs_are_unchanged(self):
        mutex = self.mutex()
        expected = supervisor_instance_binding(self.binding)
        self.assertIs(mutex._supervisor_policy_binding, self.binding)
        self.assertEqual((mutex.name, mutex.logon_id, mutex.instance_id),
                         (expected.name, expected.logon_id, expected.instance_id))
        self.assertNotEqual(mutex.name, self.binding.name)
        create = next(call for call in self.backend.calls if call[0] == "create")
        self.assertEqual(create[2:], (expected.name, LOGON, OWNER))
        self.backend.wait_result = True
        with mutex.acquire(timeout_ms=250) as lease:
            self.assertIs(type(lease), native.PolicyMutexLease)
            self.assertEqual((lease.name, lease.instance_id, lease.logon_id, lease.abandoned),
                             (expected.name, expected.instance_id, LOGON, True))
        self.assertEqual(sum(call[0] == "release" for call in self.backend.calls), 1)

    def test_retained_singleton_allows_rpc_but_actual_policy_and_job_mutexes_still_block(self):
        singleton = self.mutex()
        policy = self.mutex(policy=True)
        job = self.mutex(binding=PolicyBinding(str(uuid4()), LOGON), policy=True)
        with singleton.acquire():
            key = (threading.current_thread(), singleton.name)
            self.assertIn(key, native._SUPERVISOR_THREAD_NAMES)
            self.assertNotIn(key, native._THREAD_NAMES)
            self.assertFalse(native.current_thread_holds_mutex())
            _no_mutex()
            for critical in (policy, job):
                with critical.acquire():
                    self.assertTrue(native.current_thread_holds_mutex())
                    with self.assertRaisesRegex(ExperimentChildError, "lock_held"):
                        _no_mutex()
                self.assertFalse(native.current_thread_holds_mutex())
                _no_mutex()
        self.assertNotIn(key, native._SUPERVISOR_THREAD_NAMES)

    def test_same_name_recursion_is_rejected_between_typed_and_legacy_owners(self):
        singleton = self.mutex()
        legacy = self.mutex(binding=supervisor_instance_binding(self.binding), policy=True)
        for outer, inner in ((singleton, legacy), (legacy, singleton)):
            with outer.acquire():
                calls_before = sum(call[0] == "wait" for call in self.backend.calls)
                with self.assertRaisesRegex(native.NativePolicyMutexError, "recursive_entry"):
                    with inner.acquire():
                        self.fail("same kernel name acquired recursively")
                self.assertEqual(sum(call[0] == "wait" for call in self.backend.calls), calls_before)

    def test_separate_typed_objects_keep_the_same_singleton_name(self):
        first, second = self.mutex(), self.mutex()
        self.assertEqual(first.name, second.name)
        with first.acquire():
            with self.assertRaisesRegex(native.NativePolicyMutexError, "recursive_entry"):
                with second.acquire():
                    self.fail("second owner bypassed singleton")
        with second.acquire():
            _no_mutex()

    def test_arbitrary_names_ids_subclasses_and_tracking_switches_are_not_constructor_inputs(self):
        class Derived(native.NativeSupervisorInstanceMutex):
            pass
        for invalid in (self.binding.name, self.binding.instance_id, self.binding.__dict__, None):
            with self.subTest(invalid=type(invalid).__name__):
                with self.assertRaisesRegex(native.NativePolicyMutexError, "binding_invalid"):
                    native.NativeSupervisorInstanceMutex(invalid)
        with self.assertRaisesRegex(native.NativePolicyMutexError, "binding_invalid"):
            Derived(self.binding)
        with self.assertRaises(TypeError):
            native.NativeSupervisorInstanceMutex(LOGON, self.binding.instance_id)
        with self.assertRaises(TypeError):
            native.NativePolicyMutex(LOGON, self.binding.instance_id, track=False)
        self.assertEqual(self.backend.calls, [])

    def test_changed_original_binding_or_name_cannot_hide_an_arbitrary_policy_lock(self):
        mutex = self.mutex()
        for field, value in (("_supervisor_policy_binding", replace(self.binding)),
                             ("_name", self.binding.name),
                             ("_instance_id", self.binding.instance_id)):
            original = getattr(mutex, field)
            try:
                setattr(mutex, field, value)
                with self.assertRaisesRegex(native.NativePolicyMutexError, "binding_changed"):
                    with mutex.acquire():
                        self.fail("changed singleton binding acquired")
            finally:
                setattr(mutex, field, original)
        self.assertFalse(any(call[0] == "wait" for call in self.backend.calls))

    def test_timeout_retires_only_its_lifetime_wait_registration(self):
        singleton = self.mutex()
        policy = self.mutex(policy=True)
        with policy.acquire():
            self.backend.wait_error = native.NativePolicyMutexError("policy_mutex_timeout")
            with self.assertRaisesRegex(native.NativePolicyMutexError, "timeout"):
                with singleton.acquire():
                    self.fail("timed out")
            self.assertNotIn((threading.current_thread(), singleton.name), native._SUPERVISOR_THREAD_NAMES)
            self.assertTrue(native.current_thread_holds_mutex())
            with self.assertRaisesRegex(ExperimentChildError, "lock_held"):
                _no_mutex()
            self.backend.wait_error = None

    def test_unknown_wait_keeps_original_lifetime_custody_and_refuses_close(self):
        mutex = self.mutex()
        self.backend.wait_error = RuntimeError("fixture wait interruption")
        with self.assertRaisesRegex(RuntimeError, "wait interruption"):
            with mutex.acquire():
                self.fail("unknown wait")
        self.assertTrue(mutex._waiting)
        self.assertIn((threading.current_thread(), mutex.name), native._SUPERVISOR_THREAD_NAMES)
        with self.assertRaisesRegex(native.NativePolicyMutexError, "busy"):
            mutex.close()

    def test_release_failure_preserves_native_owner_and_lifetime_registration(self):
        mutex = self.mutex()
        self.backend.release_error = native.NativePolicyMutexError("policy_mutex_release_failed", 288)
        with self.assertRaisesRegex(native.NativePolicyMutexError, "release_failed"):
            with mutex.acquire():
                pass
        self.assertIs(mutex._owner, threading.current_thread())
        self.assertIn((threading.current_thread(), mutex.name), native._SUPERVISOR_THREAD_NAMES)
        with self.assertRaisesRegex(native.NativePolicyMutexError, "busy"):
            mutex.close()

    def test_foreign_thread_and_process_cannot_release_original_owner(self):
        mutex = self.mutex()
        errors = []
        def foreign():
            try:
                mutex._release()
            except native.NativePolicyMutexError as error:
                errors.append(error.reason)
        with mutex.acquire():
            thread = threading.Thread(target=foreign)
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, ["policy_mutex_not_owner_thread"])
            with patch.object(native.os, "getpid", return_value=os.getpid() + 1):
                with self.assertRaisesRegex(native.NativePolicyMutexError, "foreign_process"):
                    mutex._release()
            self.assertIs(mutex._owner, threading.current_thread())
        self.assertEqual(sum(call[0] == "release" for call in self.backend.calls), 1)

    def test_close_failure_retains_handle_and_does_not_fabricate_success(self):
        mutex = self.mutex()
        handle = mutex._handle
        self.backend.close_error = native.NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        with self.assertRaisesRegex(native.NativePolicyMutexError, "handle_close_failed"):
            mutex.close()
        self.assertEqual(mutex._handle, handle)
        self.backend.close_error = None
        mutex.close()
        self.assertIsNone(mutex._handle)

    def test_ordinary_supervisor_startup_default_uses_typed_original_binding(self):
        fixture = startup_fixture.SupervisorStartupTests(
            "test_fresh_ledger_pins_binding_retains_exact_self_and_mutex_until_close")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.process.identity = fixture.current.identity
        owner = SupervisorStartup(fixture.store, fixture.journal, current=fixture.current)
        self.addCleanup(fixture.cleanup_owner, owner)
        owner.acquire()
        self.addCleanup(self.cleanup_fixture, owner._mutex)
        self.assertIs(type(owner._mutex), native.NativeSupervisorInstanceMutex)
        self.assertIs(owner._mutex._supervisor_policy_binding, owner.binding)
        self.assertEqual(owner.instance_binding.name, owner._mutex.name)
        owner.assert_held()
        owner.assert_fresh()
        _no_mutex()
        policy = self.mutex(binding=owner.binding, policy=True)
        with policy.acquire():
            with self.assertRaisesRegex(ExperimentChildError, "lock_held"):
                _no_mutex()
        owner.close()
        self.assertTrue(owner._closed)
        self.assertFalse(native.current_thread_holds_mutex())
