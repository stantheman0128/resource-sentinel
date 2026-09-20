"""Portable callback/custody tests plus an explicitly selected native smoke.

The default module suite uses only a fake Powrprof backend. It never suspends
the host. Registration smoke is selectable by its class/test name; even a pass
does not establish suspend/resume delivery latency or satisfy P5.
"""
import ctypes as C
import gc
import os
import unittest
from unittest.mock import patch
import weakref

from tests.windows import adaptive_power as power


class FakeBackend:
    """Explicit portable registration model; no OS registration exists."""
    def __init__(self):
        self.handle = 700
        self.register_code = 0
        self.unregister_code = 0
        self.register_error = None
        self.unregister_error = None
        self.on_register = None
        self.on_unregister = None
        self.context = None
        self.parameters_ref = None
        self.unregistered = []

    def register(self, parameters, registration):
        self.context = parameters.Context
        self.parameters_ref = weakref.ref(parameters)
        if self.handle is not None:
            registration.value = self.handle
        if self.on_register is not None:
            self.on_register()
        if self.register_error is not None:
            raise self.register_error
        return self.register_code

    def unregister(self, registration):
        self.unregistered.append(registration)
        if self.parameters_ref() is None:
            raise AssertionError("callback_parameters_released_before_unregister")
        if self.on_unregister is not None:
            self.on_unregister()
        if self.unregister_error is not None:
            raise self.unregister_error
        return self.unregister_code

    def notify(self, event=4):
        # Invoke the actual C trampoline through its copied numeric context.
        # No captured Python owner/parameters artificially extend its lifetime.
        return power._CALLBACK(self.context, event, None)


class FakeFunction:
    def __init__(self, function):
        self.function = function
        self.restype, self.argtypes = None, None

    def __call__(self, *args):
        return self.function(*args)


class PowerWitnessTests(unittest.TestCase):
    def open(self, backend=None):
        backend = FakeBackend() if backend is None else backend
        witness = power.NativePowerWitness.open(backend=backend)
        self.addCleanup(witness.close)
        return witness, backend

    def discard_uncertain_fixture(self, witness):
        # The real implementation deliberately offers no abandonment API for an
        # unknown native completion. Only this backend has no OS registration;
        # release its synthetic roots after asserting the retention contract.
        self.assertIsInstance(witness._backend, FakeBackend)
        power._RETAINED.pop(witness._context, None)

    def test_stable_snapshot_is_an_opaque_same_generation_identity(self):
        witness, backend = self.open()
        token = witness.snapshot()
        self.assertIs(token, witness.snapshot())
        self.assertIs(type(token), object)
        self.assertIsNone(witness.assert_current(token))
        self.assertEqual(backend.unregistered, [])

    def test_each_suspend_resume_notification_invalidates_the_prior_token(self):
        witness, backend = self.open()
        for event in (4, 7, 18):
            with self.subTest(event=event):
                before = witness.snapshot()
                self.assertEqual(backend.notify(event), 0)
                with self.assertRaisesRegex(power.PowerContinuityError, "power_continuity_changed"):
                    witness.assert_current(before)
                after = witness.snapshot()
                self.assertIsNot(before, after)
                witness.assert_current(after)

    def test_tokens_from_other_witnesses_or_serialized_values_are_rejected(self):
        first, _ = self.open()
        second, _ = self.open()
        for token in (second.snapshot(), None, 1, "generation", {"generation": 0}, object()):
            with self.subTest(kind=type(token).__name__), self.assertRaises(power.PowerContinuityError):
                first.assert_current(token)
        first.assert_current(first.snapshot())

    def test_callback_exception_is_caught_at_the_abi_and_permanently_invalidates(self):
        witness, backend = self.open()
        token = witness.snapshot()
        with patch.object(witness, "_notification", side_effect=MemoryError("fixture_callback_fault")):
            self.assertEqual(backend.notify(), 31)
        for operation in (witness.snapshot, lambda: witness.assert_current(token)):
            with self.assertRaisesRegex(power.PowerContinuityError, "power_callback_failed"):
                operation()

    def test_unknown_notification_fails_closed_instead_of_creating_a_fresh_valid_token(self):
        witness, backend = self.open()
        self.assertEqual(backend.notify(0xFFFF), 87)
        with self.assertRaisesRegex(power.PowerContinuityError, "power_callback_failed"):
            witness.snapshot()

    def test_callback_contention_never_waits_and_marks_observation_unknown(self):
        witness, backend = self.open()
        token = witness.snapshot()
        with witness._state_lock:
            self.assertEqual(backend.notify(), 31)
        with self.assertRaises(power.PowerContinuityError):
            witness.assert_current(token)

    def test_snapshot_contention_is_fail_closed_and_does_not_wait(self):
        witness, _ = self.open()
        token = witness.snapshot()
        with witness._state_lock:
            with self.assertRaisesRegex(power.PowerContinuityError, "power_observation_contended"):
                witness.snapshot()
        with self.assertRaises(power.PowerContinuityError):
            witness.assert_current(token)

    def test_inline_notification_during_register_is_rooted_before_baseline(self):
        backend = FakeBackend()
        observed = []
        def registering():
            owner = power._RETAINED[backend.context]
            before = owner._generation
            observed.append(backend.notify(18))
            observed.append(owner._generation is not before)
        backend.on_register = registering
        witness, _ = self.open(backend)
        self.assertEqual(observed, [0, True])
        witness.assert_current(witness.snapshot())

    def test_callback_failure_during_register_cleans_up_and_never_returns_a_witness(self):
        backend = FakeBackend()
        backend.on_register = lambda: backend.notify(999)
        with self.assertRaisesRegex(power.PowerContinuityError, "power_callback_failed"):
            power.NativePowerWitness.open(backend=backend)
        self.assertEqual(backend.unregistered, [backend.handle])
        self.assertNotIn(backend.context, power._RETAINED)

    def test_known_failed_register_without_handle_has_no_successful_token_or_retained_registration(self):
        backend = FakeBackend()
        backend.handle, backend.register_code = None, 5
        with self.assertRaises(power.PowerContinuityError) as failed:
            power.NativePowerWitness.open(backend=backend)
        self.assertEqual(failed.exception.error_code, 5)
        self.assertEqual(backend.unregistered, [])
        self.assertNotIn(backend.context, power._RETAINED)

    def test_success_code_without_handle_is_uncertain_and_cannot_mint_a_snapshot(self):
        backend = FakeBackend()
        backend.handle = None
        with self.assertRaises(power.PowerContinuityError) as failed:
            power.NativePowerWitness.open(backend=backend)
        witness = failed.exception.power_witness
        self.addCleanup(self.discard_uncertain_fixture, witness)
        self.assertIs(power._RETAINED[backend.context], witness)
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()
        with self.assertRaisesRegex(power.PowerContinuityError, "power_registration_outcome_unknown"):
            witness.close()
        self.assertEqual(backend.unregistered, [])

    def test_failed_register_with_nonnull_output_is_not_a_proven_owned_registration(self):
        backend = FakeBackend()
        backend.register_code = 5
        with self.assertRaises(power.PowerContinuityError) as failed:
            power.NativePowerWitness.open(backend=backend)
        witness = failed.exception.power_witness
        self.addCleanup(self.discard_uncertain_fixture, witness)
        self.assertIs(power._RETAINED[backend.context], witness)
        self.assertIsNotNone(backend.parameters_ref())
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()
        with self.assertRaisesRegex(power.PowerContinuityError, "power_registration_outcome_unknown"):
            witness.close()
        self.assertEqual(backend.unregistered, [])

    def test_confirmed_register_with_callback_fault_retains_failed_cleanup_for_exact_retry(self):
        backend = FakeBackend()
        backend.on_register = lambda: backend.notify(999)
        backend.unregister_code = 170
        with self.assertRaisesRegex(power.PowerContinuityError, "power_callback_failed") as failed:
            power.NativePowerWitness.open(backend=backend)
        witness = failed.exception.power_witness
        self.assertIs(power._RETAINED[backend.context], witness)
        self.assertIsNotNone(backend.parameters_ref())
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()
        backend.unregister_code = 0
        witness.close()
        self.assertEqual(backend.unregistered, [backend.handle, backend.handle])
        self.assertNotIn(backend.context, power._RETAINED)

    def test_known_unregister_failure_keeps_roots_and_retry_does_not_restore_continuity(self):
        witness, backend = self.open()
        token = witness.snapshot()
        parameters = witness._parameters
        backend.unregister_code = 5
        with self.assertRaises(power.PowerContinuityError) as failed:
            witness.close()
        self.assertIs(failed.exception.power_witness, witness)
        self.assertEqual(failed.exception.error_code, 5)
        self.assertIs(power._RETAINED[backend.context], witness)
        self.assertIs(witness._parameters, parameters)
        with self.assertRaises(power.PowerContinuityError):
            witness.assert_current(token)
        self.assertEqual(backend.notify(), 0)
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()
        backend.unregister_code = 0
        witness.close()
        self.assertEqual(backend.unregistered, [backend.handle, backend.handle])

    def test_unknown_unregister_completion_never_reuses_a_possibly_freed_registration(self):
        backend = FakeBackend()
        witness = power.NativePowerWitness.open(backend=backend)
        self.addCleanup(self.discard_uncertain_fixture, witness)
        token = witness.snapshot()
        backend.unregister_error = RuntimeError("fixture_native_return_lost")
        with self.assertRaisesRegex(power.PowerContinuityError, "power_unregister_outcome_unknown"):
            witness.close()
        backend.unregister_error = None
        with self.assertRaisesRegex(power.PowerContinuityError, "power_unregister_outcome_unknown"):
            witness.close()
        self.assertEqual(backend.unregistered, [backend.handle])
        self.assertIs(power._RETAINED[backend.context], witness)
        with self.assertRaises(power.PowerContinuityError):
            witness.assert_current(token)

    def test_interruption_after_successful_unregister_before_publication_never_retries(self):
        backend = FakeBackend()
        witness = power.NativePowerWitness.open(backend=backend)
        self.addCleanup(self.discard_uncertain_fixture, witness)
        underlying = witness._state_lock
        class InterruptedPublicationLock:
            def __init__(self):
                self.entries = 0
            def acquire(self, *args, **kwargs):
                return underlying.acquire(*args, **kwargs)
            def release(self):
                underlying.release()
            def __enter__(self):
                self.entries += 1
                if self.entries == 2:
                    raise RuntimeError("fixture_post_unregister_publication_lost")
                underlying.acquire()
                return self
            def __exit__(self, *args):
                underlying.release()
        witness._state_lock = InterruptedPublicationLock()
        with self.assertRaisesRegex(RuntimeError, "fixture_post_unregister_publication_lost"):
            witness.close()
        self.assertEqual(backend.unregistered, [backend.handle])
        self.assertIs(power._RETAINED[backend.context], witness)
        with self.assertRaisesRegex(power.PowerContinuityError, "power_unregister_outcome_unknown"):
            witness.close()
        self.assertEqual(backend.unregistered, [backend.handle])
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()

    def test_close_invalidates_before_native_call_without_holding_callback_lock(self):
        witness, backend = self.open()
        token, callbacks = witness.snapshot(), []
        def unregistering():
            with self.assertRaises(power.PowerContinuityError):
                witness.assert_current(token)
            callbacks.append(backend.notify(7))
        backend.on_unregister = unregistering
        witness.close()
        witness.close()
        self.assertEqual(callbacks, [0])
        self.assertEqual(backend.unregistered, [backend.handle])
        self.assertIsNone(witness._parameters)
        self.assertIsNone(witness._registration.value)
        with self.assertRaises(power.PowerContinuityError):
            witness.snapshot()

    def test_dropped_python_owner_remains_rooted_until_successful_unregister(self):
        backend = FakeBackend()
        witness = power.NativePowerWitness.open(backend=backend)
        context, reference = backend.context, weakref.ref(witness)
        self.addCleanup(lambda: power._RETAINED[context].close() if context in power._RETAINED else None)
        del witness
        gc.collect()
        self.assertIsNotNone(reference())
        self.assertIsNotNone(backend.parameters_ref())
        self.assertIs(power._RETAINED[context], reference())
        reference().close()
        gc.collect()
        self.assertIsNone(reference())
        self.assertIsNone(backend.parameters_ref())

    def test_retired_callback_context_is_inert_and_never_reused_for_new_witness(self):
        first, backend = self.open()
        context = backend.context
        first.close()
        second, later = self.open()
        token = second.snapshot()
        self.assertNotEqual(context, later.context)
        self.assertEqual(power._CALLBACK(context, 4, None), 6)
        second.assert_current(token)

    def test_body_exception_keeps_primary_error_and_retains_failed_cleanup(self):
        witness, backend = self.open()
        backend.unregister_code = 170
        original = ValueError("fixture_recovery_failure")
        with self.assertRaises(ValueError) as failed:
            with witness:
                raise original
        self.assertIs(failed.exception, original)
        self.assertIn("power_witness_cleanup_failed", original.__notes__)
        self.assertIs(original.power_witness, witness)
        backend.unregister_code = 0
        witness.close()

    def test_real_backend_binds_powrprof_dword_callback_layout_and_exact_unregister(self):
        received = {}
        def register(flags, recipient, output):
            parameters = C.cast(recipient, C.POINTER(power._SubscribeParameters)).contents
            received["flags"], received["context"] = flags, parameters.Context
            received["callback"] = parameters.Callback(parameters.Context, 18, None)
            C.cast(output, C.POINTER(C.c_void_p)).contents.value = 0xABC
            return 0
        def unregister(handle):
            received["unregister"] = handle.value
            return 0
        class FakePowrprof:
            pass
        dll = FakePowrprof()
        dll.PowerRegisterSuspendResumeNotification = FakeFunction(register)
        dll.PowerUnregisterSuspendResumeNotification = FakeFunction(unregister)
        backend = power._WindowsBackend(dll=dll)
        witness = power.NativePowerWitness.open(backend=backend)
        try:
            witness.assert_current(witness.snapshot())
        finally:
            witness.close()
        self.assertIs(dll.PowerRegisterSuspendResumeNotification.restype, C.c_uint32)
        self.assertIs(dll.PowerUnregisterSuspendResumeNotification.restype, C.c_uint32)
        self.assertEqual(dll.PowerRegisterSuspendResumeNotification.argtypes,
                         [C.c_uint32, C.c_void_p, C.POINTER(C.c_void_p)])
        self.assertEqual(dll.PowerUnregisterSuspendResumeNotification.argtypes, [C.c_void_p])
        self.assertEqual(C.sizeof(power._SubscribeParameters), C.sizeof(C.c_void_p) * 2)
        self.assertEqual(power._SubscribeParameters.Context.offset, C.sizeof(C.c_void_p))
        self.assertEqual((received["flags"], received["callback"], received["unregister"]), (2, 0, 0xABC))


@unittest.skipUnless(os.name == "nt", "native power registration requires Windows")
class NativePowerWitnessSmokeTests(unittest.TestCase):
    def test_native_register_snapshot_assert_unregister(self):
        """Read-only registration only; no sleep, Job or OS-control operation."""
        witness = power.NativePowerWitness.open()
        try:
            token = witness.snapshot()
            witness.assert_current(token)
        finally:
            witness.close()  # no retry that could mask a failed first unregister
        self.assertEqual(witness._phase, "closed")
        self.assertIsNone(witness._registration.value)
        self.assertNotIn(witness._context, power._RETAINED)
        with self.assertRaises(power.PowerContinuityError):
            witness.assert_current(token)


def load_tests(loader, standard_tests, pattern):
    # Native smoke must be explicitly selected by class/test name. Ordinary
    # module/discovery execution is portable even when it runs on Windows.
    return loader.loadTestsFromTestCase(PowerWitnessTests)


if __name__ == "__main__":
    unittest.main()
