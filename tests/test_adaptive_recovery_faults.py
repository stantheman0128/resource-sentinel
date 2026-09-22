"""S3 bootstrap source boundary tests, without processes or Windows mutation."""
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, PropertyMock, patch

from tests.fixtures import adaptive_recovery_host as fixture
from tests.windows.adaptive_recovery_runner import CaseSpec, RawEvents, RecoveryRunUnavailable


class RecoveryBootstrapTests(unittest.TestCase):
    def test_installed_flush_hook_captures_actual_applied_action_but_never_restored_audit(self):
        from sentinel.adaptive.contracts import ControlProposal, RecoveryManifest
        from sentinel.adaptive.control_slot import ControlAction
        from sentinel.adaptive.guardian_control import GuardianControl
        from tests.test_adaptive_recovery_runner import evidence
        spec, _, events, _ = evidence("query_after_audit_before")
        recorded = next(item for item in events if item["event"] == "control_cutpoint")
        proposal = ControlProposal.from_dict(recorded["proposal"])
        manifest = RecoveryManifest.from_dict(recorded["manifest"])
        action = ControlAction(**recorded["action"])
        entry = SimpleNamespace(execution_id=manifest.execution_id,
                                job=SimpleNamespace(nonce=manifest.creation_nonce))
        for state in ("APPLIED", "RESTORED"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                (path / "arm-fault").touch()
                hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
                control = SimpleNamespace(_actions={manifest.execution_id: [replace(action, action_state=state)]},
                    lifecycle=SimpleNamespace(_manifest=Mock(return_value=manifest)),
                    owner=SimpleNamespace(guardian=SimpleNamespace(identity=manifest.guardian_identity)))
                hooks.control = control
                with ExitStack() as stack:
                    original = stack.enter_context(patch.object(GuardianControl, "_flush", return_value=7))
                    stack.enter_context(patch.object(fixture, "_tick", return_value=recorded["tick"]))
                    hit = stack.enter_context(patch.object(hooks, "hit"))
                    hooks.install_guardian(stack, lambda profile: None)
                    with hooks.proposal_context(proposal, entry):
                        self.assertEqual(GuardianControl._flush(control, manifest.execution_id, {}), 7)
                    original.assert_called_once_with(control, manifest.execution_id, {})
                    if state == "APPLIED":
                        cut, = hooks.raw.records
                        self.assertEqual(cut["event"], "control_cutpoint")
                        self.assertEqual(cut["proposal"], proposal.to_dict())
                        self.assertEqual(cut["manifest"], manifest.to_dict())
                        self.assertEqual(cut["action"], recorded["action"])
                        self.assertEqual(cut["action_id"], action.action_id)
                        hit.assert_called_once_with("query_after_audit_before", cutpoint=cut)
                    else:
                        hit.assert_not_called()
                        control.lifecycle._manifest.assert_not_called()
                        self.assertEqual(hooks.raw.records, [])
                self.assertIsNone(hooks._proposal_context)

    def test_control_context_interrupt_restores_original_owner_and_pending_intent(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "intent_before", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            original_context, original_intent = object(), object()
            hooks._proposal_context, hooks._published_intent = original_context, original_intent
            with self.assertRaises(KeyboardInterrupt):
                with hooks.proposal_context(object(), object(), previous_lease=10):
                    self.assertIsNone(hooks._published_intent)
                    raise KeyboardInterrupt()
            self.assertIs(hooks._proposal_context, original_context)
            self.assertIs(hooks._published_intent, original_intent)

    def test_bound_wrapper_uses_created_process_owner_and_process_identity_root(self):
        from sentinel.adaptive.contracts import ProcessIdentity
        from sentinel.adaptive.launcher import ManagedLauncher
        from sentinel.adaptive.native_launcher import CreatedProcess
        from sentinel.adaptive.native_job import NativeJob, JobAccess
        from tests.test_adaptive_guardian_launch import ProcessBackend, LOGON
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "wrapper_loss", 1, "a" * 32, 1)
        backend = ProcessBackend()
        current = backend.process(ProcessIdentity(fixture.os.getpid(), 134343072000000101, LOGON))
        self.addCleanup(current.close)
        root = ProcessIdentity(fixture.os.getpid() + 1, 134343072000000102, LOGON)
        # Real owner classes over explicit native observations; no native DLL
        # or process is started. This matches ManagedLauncher._root's actual
        # ProcessIdentity and its separate CreatedProcess custody contract.
        launcher = object.__new__(ManagedLauncher)
        launcher._bound, launcher._root = True, root
        launcher._snapshot = SimpleNamespace(execution_id="95a9131d-eedc-493e-8839-a6820e2eed5e")
        launcher.admission = SimpleNamespace(_process=current)
        launcher.process = CreatedProcess(SimpleNamespace(), LOGON)
        launcher.job = NativeJob("fixture", "b" * 32, LOGON, JobAccess.LAUNCH, SimpleNamespace())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "arm-fault").touch()
            hooks = fixture.FaultHooks(path, spec, "wrapper", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture, "_tick", return_value=2), patch.object(fixture.os, "_exit") as exit_process, \
                    patch.object(NativeJob, "handle", new_callable=PropertyMock, return_value=7000), \
                    patch.object(launcher.job, "accounting", return_value=SimpleNamespace(active_processes=2)), \
                    patch.object(launcher.job, "query_cpu", return_value=SimpleNamespace(flags=5)), \
                    patch.object(launcher.process, "full_identity", return_value=root) as identity, \
                    patch.object(launcher.process, "is_in_job", return_value=True) as membership:
                hooks.wrapper_loss(launcher)
                identity.assert_called_once_with(expected_logon_id=LOGON)
                membership.assert_called_once_with(launcher.job)
                exit_process.assert_called_once_with(197)
            self.assertTrue(hooks.fired)
            self.assertEqual([row["event"] for row in hooks.raw.records],
                             ["fault_injected", "process_fault_termination"])
            self.assertEqual(hooks.raw.records[0]["actor_identity"], current.identity.to_dict())

    def test_wrapper_loss_requires_original_bound_native_owner(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "wrapper_loss", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "arm-fault").touch()
            hooks = fixture.FaultHooks(path, spec, "wrapper", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture, "_tick", return_value=2), patch.object(fixture.os, "_exit") as exit_process:
                with self.assertRaisesRegex(RecoveryRunUnavailable, "original_bound_wrapper"):
                    hooks.wrapper_loss(SimpleNamespace(_bound=True))
                self.assertFalse(hooks.fired)
                exit_process.assert_not_called()

    def test_real_isolated_audit_lock_blocks_writes_until_release_without_changing_rows(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "audit_unavailable", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            db = path / "sentinel.db"
            connection = sqlite3.connect(db, timeout=0, isolation_level=None)
            try:
                connection.execute("CREATE TABLE evidence(value TEXT)")
                connection.execute("INSERT INTO evidence VALUES ('original')")
                hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
                hooks.control = SimpleNamespace(store=SimpleNamespace(db_path=db))
                entry = SimpleNamespace(execution_id="95a9131d-eedc-493e-8839-a6820e2eed5e",
                                        job=SimpleNamespace(nonce="b" * 32))
                outage = fixture.AuditOutage(hooks, entry)
                with patch.object(fixture, "_tick", return_value=2):
                    try:
                        outage.start()
                        self.assertTrue(outage.locked)
                        with self.assertRaises(sqlite3.OperationalError) as failure:
                            connection.execute("BEGIN IMMEDIATE")
                        self.assertIn(failure.exception.sqlite_errorcode, {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})
                        self.assertEqual(connection.execute("SELECT value FROM evidence").fetchall(), [("original",)])
                    finally:
                        (path / "release-audit").touch()
                        if outage.thread is not None:
                            outage.thread.join(timeout=2)
                    self.assertTrue(outage.done.is_set())
                    self.assertFalse(outage.thread.is_alive())
                    self.assertFalse(outage.locked)
                    self.assertIsNone(outage.error)
                    connection.execute("BEGIN IMMEDIATE")
                    connection.rollback()
                self.assertEqual([item["event"] for item in hooks.raw.records],
                                 ["audit_lock_acquired", "audit_lock_released"])
                self.assertEqual(connection.execute("SELECT value FROM evidence").fetchall(), [("original",)])
            finally:
                connection.close()

    def test_audit_outage_cannot_target_a_ledger_outside_original_case(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "audit_unavailable", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            case = path / "case"
            case.mkdir()
            db = path / "sentinel.db"
            db.touch()
            hooks = fixture.FaultHooks(case, spec, "guardian", RawEvents(spec, case / "events.jsonl"))
            hooks.control = SimpleNamespace(store=SimpleNamespace(db_path=db))
            with patch.object(fixture.threading, "Thread") as thread:
                with self.assertRaisesRegex(RecoveryRunUnavailable, "audit_daily_directory_forbidden"):
                    fixture.AuditOutage(hooks, object())
                thread.assert_not_called()

    def test_audit_deadline_and_release_do_not_block_restore_with_another_injected_error(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "audit_unavailable", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "arm-fault").touch()
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture, "_tick", return_value=spec.deadline_tick), \
                    patch.object(hooks, "scope", side_effect=AssertionError("restore blocked by expired fault")):
                hooks.audit_failure()
            (path / "release-audit").touch()
            with patch.object(fixture, "_tick", return_value=2), \
                    patch.object(hooks, "scope", side_effect=AssertionError("released fault retried")):
                hooks.audit_failure()

    def test_host_path_must_equal_original_isolated_case(self):
        with tempfile.TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            foreign = Path(directory) / "foreign"
            data.mkdir()
            foreign.mkdir()
            scope = {"data_directory": str(data), "journal_directory": str(data)}
            fixed = ["--journal-dir", str(data), "--guardian-epoch", "fixture"]
            fixture._assert_arguments_scope(["--data-dir", str(data), *fixed], scope)
            for args in (["--data-dir", str(foreign)],
                         ["--data-dir", str(data), "--data-dir=" + str(foreign)],
                         ["--data-dir", str(data), "--data=" + str(foreign)]):
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture._assert_arguments_scope([*args, *fixed], scope)
            for suffix in (["--journal-dir=" + str(foreign)], ["--journal=" + str(foreign)]):
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture._assert_arguments_scope(["--data-dir", str(data), *fixed, *suffix], scope)

    def test_unavailable_daily_provider_precedes_host_start(self):
        coverage_error = RuntimeError("original_daily_provider_missing")
        with patch.object(fixture, "load_case", return_value=(Path("test"), object(),
                {"data_directory": "test"})), patch.object(fixture, "_assert_arguments_scope"), \
                patch("tests.windows.adaptive_admission.require_continuous_admission", side_effect=coverage_error), \
                patch("sentinel.adaptive.guardian_host.main") as main:
            with self.assertRaisesRegex(RuntimeError, "original_daily_provider_missing"):
                fixture.run_role("test", "guardian", [])
            main.assert_not_called()

    def test_no_callback_or_boolean_can_replace_original_scope_bridge(self):
        for coverage in (None, SimpleNamespace(), SimpleNamespace(assert_spike_covered=Mock(return_value=True))):
            with patch.object(fixture, "load_case", return_value=(Path("test"), object(),
                    {"data_directory": "test"})), patch.object(fixture, "_assert_arguments_scope"), \
                    patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=coverage), \
                    patch("sentinel.adaptive.guardian_host.main") as main:
                with self.assertRaises(RecoveryRunUnavailable):
                    fixture.run_role("test", "guardian", [])
                main.assert_not_called()

    def test_unarmed_or_different_fault_never_exits(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "intent_before", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture.os, "_exit") as exit_process:
                hooks.hit("intent_before")
                (path / "arm-fault").touch()
                hooks.hit("set_after_query_before")
                exit_process.assert_not_called()

    def test_armed_fault_requires_actual_native_scope_before_self_exit(self):
        spec = CaseSpec("61c69f2d-ded8-49c0-8320-912633c346bf", "intent_before", 1, "a" * 32, 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "arm-fault").touch()
            hooks = fixture.FaultHooks(path, spec, "guardian", RawEvents(spec, path / "events.jsonl"))
            with patch.object(fixture, "_tick", return_value=2), patch.object(fixture.os, "_exit") as exit_process:
                with self.assertRaisesRegex(RecoveryRunUnavailable, "owner_unbound"):
                    hooks.hit("intent_before")
                self.assertFalse(hooks.fired)
                exit_process.assert_not_called()

    def test_hook_restores_original_function_after_exception(self):
        original = lambda: None
        owner = SimpleNamespace(method=original)
        replacement = lambda: 4
        with self.assertRaisesRegex(RuntimeError, "fixture"):
            with fixture._replace(owner, "method", replacement):
                self.assertIs(owner.method, replacement)
                raise RuntimeError("fixture")
        self.assertIs(owner.method, original)

    def test_cleanup_hold_keeps_every_original_owner_and_does_not_retry_close(self):
        first, second, error = Mock(), Mock(), KeyboardInterrupt()
        hold = fixture.CleanupHold((first, second), error)
        self.assertIs(hold.owners[0], first)
        self.assertIs(hold.owners[1], second)
        self.assertIs(hold.error, error)
        first.close.assert_not_called()
        second.close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
