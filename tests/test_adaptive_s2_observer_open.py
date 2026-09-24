"""Portable observer-open custody models; no Win32 operations or native gate."""
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests.windows import adaptive_win32 as native


class ObserverOpenCustodyTests(unittest.TestCase):
    def setUp(self):
        self.kernel = SimpleNamespace(OpenProcess=Mock(return_value=617), CloseHandle=Mock(return_value=1))
        self.owners = []

    def observe(self, process):
        self.owners.append(process)
        return {"pid": process.pid, "created_filetime_100ns": "12345"}

    def test_success_returns_the_original_validated_observer_without_closing_it(self):
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=self.observe):
            owner = native.ProcessHandle.open(71, 12345, terminate=True)
        self.assertIs(owner, self.owners[0])
        self.assertEqual(owner.handle, 617)
        self.kernel.OpenProcess.assert_called_once_with(0x100000 | 0x1000 | 0x0400 | 0x0001, False, 71)
        self.kernel.CloseHandle.assert_not_called()

    def test_mismatched_birth_with_positive_cleanup_keeps_original_validation_error(self):
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=self.observe):
            with self.assertRaisesRegex(ValueError, "exact process identity mismatch") as raised:
                native.ProcessHandle.open(71, 99999)
        self.assertNotIsInstance(raised.exception, native.RetainedProcessOpenError)
        self.assertIsNone(self.owners[0].handle)
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_read_failure_and_positive_close_rethrows_same_primary_object(self):
        primary = OSError("identity query failed")
        def observe(process):
            self.owners.append(process)
            raise primary
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=observe):
            with self.assertRaises(OSError) as raised:
                native.ProcessHandle.open(71)
        self.assertIs(raised.exception, primary)
        self.assertIsNone(self.owners[0].handle)
        self.assertFalse(getattr(self.owners[0], "_s2_observer_open_close_unknown", False))
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_validation_and_close_failures_keep_exact_owner_and_both_errors(self):
        primary, cleanup = OSError("identity query failed"), OSError("close failed")
        def observe(process):
            self.owners.append(process)
            raise primary
        self.kernel.CloseHandle.side_effect = cleanup
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.ProcessHandle.open(71)
            error = raised.exception
            self.assertNotIsInstance(error, native.UnsupportedCapability)
            self.assertIs(error.owner, self.owners[0])
            self.assertIs(error.primary, primary)
            self.assertIs(error.cleanup_error, cleanup)
            self.assertIs(error.__cause__, primary)
            self.assertEqual(error.cleanup_state, "unknown")
            self.assertEqual(error.reason, "s2_observer_open_cleanup_unknown")
            self.assertEqual(error.owner.handle, 617)
            self.assertTrue(error.owner._s2_observer_open_close_unknown)
            with self.assertRaisesRegex(RuntimeError, "s2_observer_open_cleanup_unknown"):
                error.owner.close()
        self.kernel.OpenProcess.assert_called_once()
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_mismatched_birth_close_failure_keeps_the_original_validation_owner(self):
        cleanup = OSError("close failed")
        self.kernel.CloseHandle.side_effect = cleanup
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=self.observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.ProcessHandle.open(71, 99999)
        self.assertIs(raised.exception.owner, self.owners[0])
        self.assertIsInstance(raised.exception.primary, ValueError)
        self.assertIs(raised.exception.cleanup_error, cleanup)
        self.assertEqual(raised.exception.owner.handle, 617)

    def test_baseexceptions_at_both_boundaries_are_preserved_and_not_retried(self):
        primary, cleanup = KeyboardInterrupt(), KeyboardInterrupt()
        def observe(process):
            self.owners.append(process)
            raise primary
        self.kernel.CloseHandle.side_effect = cleanup
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.ProcessHandle.open(71)
            self.assertIs(raised.exception.primary, primary)
            self.assertIs(raised.exception.cleanup_error, cleanup)
            with self.assertRaisesRegex(RuntimeError, "s2_observer_open_cleanup_unknown"):
                raised.exception.owner.close()
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_successful_native_close_with_interrupted_ack_is_still_unknown(self):
        primary, interrupted = ValueError("identity invalid"), KeyboardInterrupt()
        def observe(process):
            self.owners.append(process)
            raise primary
        def check(ok, operation):
            self.assertTrue(ok)
            if operation == "CloseHandle(process)":
                raise interrupted
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native, "_check", side_effect=check), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.ProcessHandle.open(71)
            self.assertIs(raised.exception.cleanup_error, interrupted)
            self.assertEqual(raised.exception.owner.handle, 617)
            with self.assertRaisesRegex(RuntimeError, "s2_observer_open_cleanup_unknown"):
                raised.exception.owner.close()
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_reported_native_close_failure_also_quarantines_original_owner(self):
        cleanup = OSError("native close returned false")
        self.kernel.CloseHandle.return_value = 0
        def check(ok, operation):
            if not ok:
                self.assertEqual(operation, "CloseHandle(process)")
                raise cleanup
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native, "_check", side_effect=check), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=self.observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.ProcessHandle.open(71, 99999)
            self.assertIs(raised.exception.cleanup_error, cleanup)
            with self.assertRaisesRegex(RuntimeError, "s2_observer_open_cleanup_unknown"):
                raised.exception.owner.close()
        self.kernel.CloseHandle.assert_called_once_with(617)

    def test_current_identity_propagates_retained_open_owner(self):
        primary, cleanup = OSError("identity query failed"), OSError("close failed")
        self.kernel.CloseHandle.side_effect = cleanup
        def observe(process):
            self.owners.append(process)
            raise primary
        with patch.object(native, "_api", return_value=(self.kernel, None, None)), \
                patch.object(native.os, "getpid", return_value=71), \
                patch.object(native.ProcessHandle, "identity", autospec=True, side_effect=observe):
            with self.assertRaises(native.RetainedProcessOpenError) as raised:
                native.current_identity()
        self.assertIs(raised.exception.owner, self.owners[0])
        self.assertEqual(raised.exception.owner.pid, 71)
        self.assertIs(raised.exception.primary, primary)
        self.assertIs(raised.exception.cleanup_error, cleanup)
        self.kernel.OpenProcess.assert_called_once()
        self.kernel.CloseHandle.assert_called_once()


if __name__ == "__main__":
    unittest.main()
