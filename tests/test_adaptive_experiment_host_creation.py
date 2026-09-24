"""Synthetic ABI custody regressions; no native capability or launch evidence.

The exact scope object below is deliberately built with class-level in-memory
gate doubles. Connected scope/readiness/publication tests supply the real gate;
these cases isolate retained native output and failure ordering without creating
processes, Jobs, a daily reservation, or invoking any Windows API.
"""
import ctypes as C
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import identity as identities
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from sentinel.adaptive.experiment_host_ledger import MemberClaim


IDENTITY = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class IdentityBackend:
    def __init__(self):
        self.value = IDENTITY
        self.state = IdentityStatus.ALIVE
        self.duplicates, self.closes, self.queries = [], [], []
        self.duplicate_error = self.identity_error = self.close_error = None

    def duplicate_into(self, source, output, *, source_process=None):
        if source_process is not None:
            raise AssertionError("unexpected remote source")
        self.duplicates.append(source)
        output.value = 900
        if self.duplicate_error:
            raise self.duplicate_error

    def identity(self, handle):
        self.queries.append(handle)
        if self.identity_error:
            raise self.identity_error
        return self.value

    def wait(self, handle):
        self.queries.append(handle)
        return self.state

    def close(self, handle):
        self.closes.append(handle)
        if self.close_error:
            raise self.close_error


class CreationCustodyTests(unittest.TestCase):
    def setUp(self):
        self.scope = scopes.ProductionExperimentScope(_token=scopes._CREATE)
        self.member = MemberClaim(str(uuid4()), "infrastructure", "helper",
                                  ResourceDemand(cpu_units=1, physical_bytes=1 << 29,
                                                 commit_bytes=1 << 29, io_slots=0))
        self.scope.demand, self.scope.spec = object(), object()
        self.scope.plan = SimpleNamespace(members=(self.member,))
        self.scope.process = SimpleNamespace(identity=IDENTITY)
        self.scope._prepared = True
        self.command = creation.ChildCommand("C:\\Python\\python.exe",
            ("-m", "sentinel.adaptive.experiment_host_child", "inert"), "C:\\isolated")
        self.backend = IdentityBackend()
        self.entered, self.closed, self.waited = [], [], []
        self.gate_calls = self.constructors = 0
        self.allow_gate = True
        self.reject_gate_call = None
        self.create_result = 1
        self.write_output = True
        self.create_error = None
        self.close_results = {}
        self.wait_result = 0x102

        def original(scope, demand, spec, registered=None):
            if scope is not self.scope or demand is not scope.demand or spec is not scope.spec:
                raise AssertionError("synthetic original owner mismatch")

        def gate(scope, attempt):
            original(scope, scope.demand, scope.spec)
            self.gate_calls += 1
            if not self.allow_gate or scope._sealed or self.gate_calls == self.reject_gate_call:
                raise RuntimeError("synthetic_gate_closed")
            self.assertIs(scope._attempts[self.member.member_id], attempt)

        def native_init(backend):
            self.constructors += 1
            self.assertIn(self.member.member_id, self.scope._attempts)
            backend.kernel = SimpleNamespace(CreateProcessW=self.create_native,
                CloseHandle=self.close_native, WaitForSingleObject=self.wait_native)

        for replacement in (
            patch.object(scopes.ProductionExperimentScope, "_assert_ledger_original", original),
            patch.object(scopes.ProductionExperimentScope, "_assert_creation_gate", gate, create=True),
            patch.object(creation._NativeCreation, "__init__", native_init),
            patch.object(identities, "_backend", return_value=self.backend),
        ):
            replacement.start()
            self.addCleanup(replacement.stop)

    def create_native(self, *arguments):
        self.entered.append(arguments)
        attempt = self.scope._attempts[self.member.member_id]
        info = arguments[-1]._obj
        self.assertIs(info, attempt._info_original)
        self.assertIs(arguments[1], attempt._buffer_original)
        self.assertEqual(arguments[4:7], (False, 0, None))
        self.assertIsNone(arguments[2])
        self.assertIsNone(arguments[3])
        if self.write_output:
            info.hProcess, info.hThread = 800, 801
            info.dwProcessId, info.dwThreadId = IDENTITY.pid, 102
        if self.create_error:
            raise self.create_error
        return self.create_result

    def close_native(self, handle):
        self.closed.append(handle)
        outcome = self.close_results.get(handle, 1)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def wait_native(self, handle, timeout):
        self.waited.append((handle, timeout))
        return self.wait_result

    def prepare(self):
        return creation.CreationAttempt._prepare(self.scope, self.member, self.command)

    def created(self, *, captured=True):
        attempt = self.prepare().create(self.scope)
        if captured:
            self.assertIs(attempt.capture_identity(self.scope), attempt.process)
        return attempt

    def dead(self):
        self.backend.state, self.wait_result = IdentityStatus.DEAD, 0

    def test_prepare_owns_output_before_any_native_and_rejects_second_attempt(self):
        attempt = self.prepare()
        self.assertIs(self.scope._attempts[self.member.member_id], attempt)
        self.assertIs(attempt._info, attempt._info_original)
        self.assertEqual(attempt._raw_values(), (None, None, 0, 0))
        self.assertEqual((self.constructors, self.gate_calls, self.entered), (0, 0, []))
        with self.assertRaisesRegex(creation.CreationCustodyError, "original_member_required"):
            self.prepare()

    def test_factory_requires_original_scope_and_original_member(self):
        with self.assertRaises(creation.CreationCustodyError):
            creation.CreationAttempt()
        with self.assertRaises(creation.CreationCustodyError):
            creation.CreationAttempt._prepare(SimpleNamespace(), self.member, self.command)
        with self.assertRaises(creation.CreationCustodyError):
            creation.CreationAttempt._prepare(self.scope, replace(self.member), self.command)
        self.assertEqual(self.constructors, 0)

    def test_create_plain_flags_gate_and_exact_identity_from_creation_handle(self):
        attempt = self.created()
        self.assertGreaterEqual(self.gate_calls, 4)
        self.assertEqual(self.backend.duplicates, [800])
        self.assertEqual(attempt.process.identity, IDENTITY)
        self.assertEqual(len(self.entered), 1)
        self.assertIs(attempt.observe_exit(self.scope), IdentityStatus.ALIVE)
        with self.assertRaisesRegex(creation.CreationCustodyError, "actor_exit_unverified"):
            attempt.settle_native(self.scope)
        self.assertEqual(self.closed, [])
        self.assertEqual(self.backend.closes, [])

    def test_positive_same_handle_death_closes_all_custody_once_without_aggregate_release(self):
        attempt = self.created()
        self.dead()
        self.scope._sealed = True  # settlement does not need admission reopened
        attempt.settle_native(self.scope)
        attempt.settle_native(self.scope)
        self.assertTrue(attempt.native_settled)
        self.assertEqual(self.backend.closes, [900])
        self.assertEqual(self.closed, [801, 800])
        self.assertIs(self.scope._attempts[self.member.member_id], attempt)
        self.assertFalse(attempt.never_created)

    def test_exact_false_with_empty_output_proves_never_created_and_never_retries(self):
        self.create_result, self.write_output = 0, False
        attempt = self.prepare()
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_failed"):
            attempt.create(self.scope)
        self.assertTrue(attempt.never_created)
        attempt.settle_native(self.scope)
        self.assertTrue(attempt.native_settled)
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_not_repeatable"):
            attempt.create(self.scope)
        self.assertEqual(len(self.entered), 1)
        self.assertEqual(self.closed, [])

    def test_false_with_nonzero_output_is_unknown_not_handle_ownership(self):
        self.create_result = 0
        attempt = self.prepare()
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_outcome_unknown"):
            attempt.create(self.scope)
        self.dead()
        with self.assertRaises(creation.CreationCustodyError):
            attempt.settle_native(self.scope)
        self.assertFalse(attempt.native_settled)
        self.assertEqual(self.closed, [])
        self.assertEqual(self.waited, [])

    def test_output_written_then_interrupt_keeps_original_cell_and_no_retry(self):
        self.create_error = KeyboardInterrupt()
        attempt = self.prepare()
        with self.assertRaises(KeyboardInterrupt):
            attempt.create(self.scope)
        self.assertEqual(attempt._info_original.hProcess, 800)
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_not_repeatable"):
            attempt.create(self.scope)
        self.dead()
        with self.assertRaises(creation.CreationCustodyError):
            attempt.settle_native(self.scope)
        self.assertEqual(len(self.entered), 1)
        self.assertEqual(self.closed, [])

    def test_forged_create_failure_exception_is_unknown_even_with_empty_output(self):
        self.write_output = False
        self.create_error = creation.CreationCustodyError("create_failed")
        attempt = self.prepare()
        with self.assertRaises(creation.CreationCustodyError):
            attempt.create(self.scope)
        self.assertFalse(attempt.never_created)
        with self.assertRaises(creation.CreationCustodyError):
            attempt.settle_native(self.scope)

    def test_gate_denial_before_native_does_not_load_backend(self):
        attempt = self.prepare()
        self.allow_gate = False
        with self.assertRaisesRegex(RuntimeError, "synthetic_gate_closed"):
            attempt.create(self.scope)
        self.assertEqual(self.constructors, 0)
        self.assertEqual(self.entered, [])

    def test_final_gate_denial_is_never_created_and_settles_without_retry(self):
        attempt = self.prepare()
        self.reject_gate_call = 3  # Both earlier checks pass; actual boundary refuses.
        with self.assertRaisesRegex(RuntimeError, "synthetic_gate_closed"):
            attempt.create(self.scope)
        self.assertEqual(self.gate_calls, 3)
        self.assertEqual(self.constructors, 1)
        self.assertEqual(self.entered, [])
        self.assertFalse(attempt._create_entered)
        self.assertTrue(attempt.never_created)
        with self.assertRaisesRegex(creation.CreationCustodyError, "create_not_repeatable"):
            attempt.create(self.scope)
        attempt.settle_native(self.scope)
        self.assertTrue(attempt.native_settled)
        self.assertIs(self.scope._attempts[self.member.member_id], attempt)
        self.assertEqual(self.closed, [])
        self.assertEqual(self.backend.duplicates, [])

    def test_mutable_command_buffer_or_startup_cannot_change_fixed_launch(self):
        for change in ("buffer", "startup", "info"):
            with self.subTest(change=change):
                self.scope._attempts.clear()
                attempt = self.prepare()
                if change == "buffer":
                    attempt._command_buffer.value = "changed"
                elif change == "startup":
                    attempt._startup.dwFlags = 0x100
                else:
                    attempt._info.hProcess = 999
                with self.assertRaisesRegex(creation.CreationCustodyError, "native_inputs_changed"):
                    attempt.create(self.scope)
        self.assertEqual(self.entered, [])

    def test_instance_gate_override_cannot_bypass_scope_gate(self):
        attempt = self.prepare()
        attempt._gate = lambda scope: None
        self.allow_gate = False
        with self.assertRaisesRegex(RuntimeError, "synthetic_gate_closed"):
            attempt.create(self.scope)
        self.assertEqual(self.entered, [])

    def test_replaced_raw_output_handle_or_backend_never_closes_substitute(self):
        attempt = self.created()
        self.dead()
        attempt._info.hProcess = 999
        with self.assertRaisesRegex(creation.CreationCustodyError, "creation_output_changed"):
            attempt.settle_native(self.scope)
        self.assertEqual(self.closed, [])
        attempt._info.hProcess = 800
        attempt._backend = SimpleNamespace(close=lambda handle: self.fail("substitute closed"))
        with self.assertRaisesRegex(creation.CreationCustodyError, "original_attempt_required"):
            attempt.settle_native(self.scope)
        self.assertEqual(self.closed, [])

    def test_disappeared_duplicate_handle_without_our_close_ack_is_not_settlement(self):
        attempt = self.created()
        self.dead()
        self.assertIs(attempt.observe_exit(self.scope), IdentityStatus.DEAD)
        attempt.process._handle = None
        with self.assertRaisesRegex(creation.CreationCustodyError, "identity_owner_changed"):
            attempt.settle_native(self.scope)
        self.assertFalse(attempt.native_settled)
        self.assertEqual(self.closed, [])

    def test_raw_close_false_retries_only_failed_original_handle(self):
        attempt = self.created()
        self.dead()
        self.close_results[801] = 0
        with self.assertRaisesRegex(creation.CreationCustodyError, "thread_close_failed"):
            attempt.settle_native(self.scope)
        self.assertFalse(attempt.native_settled)
        self.close_results[801] = 1
        attempt.settle_native(self.scope)
        self.assertEqual(self.closed, [801, 800, 801])
        self.assertEqual(self.backend.closes, [900])
        self.assertTrue(attempt.native_settled)

    def test_raw_close_interrupt_never_retries_uncertain_numeric_handle(self):
        attempt = self.created()
        self.dead()
        self.close_results[801] = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            attempt.settle_native(self.scope)
        self.close_results[801] = 1
        with self.assertRaisesRegex(creation.CreationCustodyError, "thread_close_outcome_unknown"):
            attempt.settle_native(self.scope)
        self.assertEqual(self.closed, [801, 800])
        self.assertFalse(attempt.native_settled)

    def test_duplicate_close_known_failure_is_retryable_without_reclosing_raw(self):
        attempt = self.created()
        self.dead()
        self.backend.close_error = identities.IdentityUnavailable("process_handle_close_failed", 6)
        with self.assertRaises(identities.IdentityUnavailable):
            attempt.settle_native(self.scope)
        self.backend.close_error = None
        attempt.settle_native(self.scope)
        self.assertEqual(self.backend.closes, [900, 900])
        self.assertEqual(self.closed, [801, 800])
        self.assertTrue(attempt.native_settled)

    def test_unknown_capture_without_cleanup_is_not_proof_no_duplicate_exists(self):
        attempt = self.created(captured=False)
        failure = KeyboardInterrupt()
        with patch.object(identities.VerifiedProcess, "duplicate_from_handle", side_effect=failure):
            with self.assertRaises(KeyboardInterrupt):
                attempt.capture_identity(self.scope)
        self.dead()
        with self.assertRaisesRegex(creation.CreationCustodyError, "identity_capture_outcome_unknown"):
            attempt.settle_native(self.scope)
        self.assertFalse(attempt.native_settled)
        self.assertEqual(self.closed, [801, 800])
        with self.assertRaises(creation.CreationCustodyError):
            attempt.capture_identity(self.scope)

    def test_output_written_then_duplicate_interrupt_keeps_capture_unsettled(self):
        attempt = self.created(captured=False)
        self.backend.duplicate_error = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt) as raised:
            attempt.capture_identity(self.scope)
        owner, = raised.exception._identity_handle_cleanup
        self.assertEqual(owner._output.value, 900)
        self.dead()
        with self.assertRaises(identities.IdentityUnavailable):
            attempt.settle_native(self.scope)
        self.assertEqual(self.backend.closes, [])
        self.assertFalse(attempt.native_settled)

    def test_failed_identity_with_positive_duplicate_cleanup_can_settle_raw_custody(self):
        attempt = self.created(captured=False)
        self.backend.identity_error = RuntimeError("synthetic query failure")
        with self.assertRaises(RuntimeError):
            attempt.capture_identity(self.scope)
        self.assertEqual(self.backend.closes, [900])
        self.dead()
        attempt.settle_native(self.scope)
        self.assertTrue(attempt.native_settled)
        self.assertIsNone(attempt.process)
        self.assertEqual(self.closed, [801, 800])

    def test_nested_token_close_failure_remains_unsettled_after_outer_duplicate_cleanup(self):
        attempt = self.created(captured=False)
        failure = identities.IdentityUnavailable("process_handle_close_failed", 6)
        failure._native_close_failed = True
        self.backend.identity_error = failure
        with self.assertRaises(identities.IdentityUnavailable):
            attempt.capture_identity(self.scope)
        self.assertEqual(self.backend.closes, [900])
        self.dead()
        with self.assertRaisesRegex(creation.CreationCustodyError, "identity_capture_outcome_unknown"):
            attempt.settle_native(self.scope)
        self.assertFalse(attempt.native_settled)


if __name__ == "__main__":
    unittest.main()
