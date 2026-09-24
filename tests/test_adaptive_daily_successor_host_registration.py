"""Original host retry across actual successor guardian registration SQL.

The child Create and process handles are explicit synthetic native resources.
Startup, history checks, epoch publication, POLICY and child registration use
their original production objects over isolated SQLite. Operator pipes and
recovery attachment are outside this bounded startup retry test.
"""
import os
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import identity
from sentinel.adaptive import supervisor_host
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.guardian_registration import GuardianRegistration
from sentinel.adaptive.recovery_owner import RetainedGuardianCreation
from tests import test_adaptive_daily_successor_epoch as epoch_fixture
from tests.test_adaptive_guardian_launch import ProcessBackend
from tests.test_adaptive_host_authority import SYNTHETIC


class CreationBackend(ProcessBackend):
    def duplicate_process(self, handle):
        return self.new_handle(self.state(handle))


class Creation:
    """One synthetic Create result; retain the raw handle until fixture exit."""
    def __init__(self, test):
        self.test = test
        self.backend = CreationBackend()
        self.process = None
        self.calls, self.closed = [], []

    def create(self, executable, arguments, cwd):
        test = self.test
        guard = test.store._policy.assert_held()
        test.assertIs(guard, test.host._initial_start_operation.guard)
        test.assertIsNone(self.process, "duplicate guardian Create")
        self.calls.append((executable, tuple(arguments), cwd, guard))
        self.process = self.backend.process(ProcessIdentity(os.getpid(),
            134343072009999999, test.host.startup.binding.logon_id))
        return SimpleNamespace(hProcess=self.process._handle, hThread=900001,
                               dwProcessId=self.process.identity.pid, dwThreadId=900002)

    def close_handle(self, handle):
        self.test.assertEqual(handle, 900001)  # Only the original thread handle closes here.
        self.closed.append(handle)

    def close_fixture(self):
        for record in self.test.host._creation_records:
            if record.get("witness") is not None:
                record["witness"].close()
        if self.process is not None:
            self.process.close()


class SuccessorHostRegistrationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = epoch_fixture.SuccessorGuardianEpochTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.store = self.fixture.supervisor, self.fixture.store
        self.epoch = self.fixture.owner
        self.host.capability = SYNTHETIC
        self.creation = Creation(self)
        self.host.creation = self.creation
        self.addCleanup(self.creation.close_fixture)

    def test_child_registration_between_original_clear_ack_loss_and_retry_does_not_remint_or_create(self):
        clear = self.store._policy._clear
        lost, original_guards = [], []
        original_fresh = self.host.startup.assert_fresh_locked

        def fresh():
            value = original_fresh()
            if self.host._initial_start_operation is not None:
                original_guards.append(self.store._policy.assert_held())
            return value

        def clear_then_lose_ack(guard):
            clear(guard)
            if (self.host.guardian is not None and not lost and
                    guard is self.host._initial_start_operation.guard):
                lost.append(guard)
                raise sqlite3.OperationalError("fixture_initial_clear_ack_lost")

        attached = object()  # Report-only attach return; no recovery authority is asserted.
        with patch.object(self.host, "_ensure_operations"), \
                patch.object(self.host, "_attach", return_value=attached) as attach, \
                patch.object(self.host, "capability_logon", return_value=self.host.startup.binding.logon_id), \
                patch.object(identity, "_backend", return_value=self.creation.backend), \
                patch.object(self.host.startup, "assert_fresh_locked", side_effect=fresh):
            with patch.object(self.store._policy, "_clear", side_effect=clear_then_lose_ack):
                first = self.host._finish_startup(None)
            self.assertEqual(first["state"], "COLD_RECOVERY_HOLD")
            self.assertTrue(first["guardian_created"])
            self.assertFalse(first["attached"])
            original = self.host.guardian
            operation = self.host._initial_start_operation
            self.assertEqual(len(lost), 1)
            self.assertIs(operation.guard, lost[0])
            self.assertTrue(operation.pending)
            self.assertFalse(self.host._initial_start_result.quarantined)
            self.assertTrue(lost[0]._native_exit_confirmed)
            self.assertTrue(lost[0]._nonce_clear_confirmed)
            self.assertIs(type(original.creation_witness), RetainedGuardianCreation)
            self.assertIs(original.process, original.creation_witness.process)
            self.assertEqual(original.process.identity, self.creation.process.identity)
            self.assertEqual(original_guards, [lost[0]])
            self.assertEqual(len(self.creation.calls), 1)
            self.assertIs(self.creation.calls[0][3], lost[0])
            self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
            attach.assert_not_called()

            revision = self.fixture.runtime()["registry_revision"]
            registration = GuardianRegistration(self.store, self.host.journal,
                guardian=self.creation.process, guardian_epoch=self.epoch.new_epoch)
            result = registration.tick()
            self.assertTrue(result.complete, result)
            self.assertEqual(self.fixture.runtime()["registry_revision"], revision + 1)
            audit = self.fixture.audits()
            with patch.object(self.epoch, "tick", side_effect=AssertionError("epoch publication repeated")), \
                    patch.object(self.epoch, "assert_complete", side_effect=AssertionError("obsolete epoch revision read")), \
                    patch.object(supervisor_host, "mint_guardian_epoch", side_effect=AssertionError("epoch reminted")), \
                    patch.object(self.creation, "create", side_effect=AssertionError("second guardian Create")), \
                    patch.object(self.host.startup, "assert_fresh", side_effect=AssertionError("replacement startup inspection")), \
                    patch.object(self.host.startup, "assert_fresh_locked", side_effect=AssertionError("second Create inspection")):
                resumed = self.host._finish_startup(None)
            self.assertTrue(resumed["attached"], resumed)
            self.assertNotIn("state", resumed)
            self.assertEqual(resumed["guardian_epoch"], self.epoch.new_epoch)
            self.assertIs(self.host._initial_start_operation, operation)
            self.assertIs(self.host.guardian, original)
            self.assertIs(self.host.supervisor, attached)
            self.assertFalse(operation.pending)
            self.assertTrue(self.host._initial_start_result.complete)
            self.assertIsNone(operation.guard)
            self.assertEqual(self.host.started_guardians, 1)
            self.assertEqual(len(self.creation.calls), 1)
            self.assertEqual(self.creation.closed, [900001])
            self.assertEqual(self.fixture.audits(), audit)
            self.assertEqual(self.fixture.runtime()["registry_revision"], revision + 1)
            attach.assert_called_once_with(original)


if __name__ == "__main__":
    unittest.main()
