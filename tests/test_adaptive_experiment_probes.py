"""Original reopened-probe custody with real isolated SQL and fake Win32 I/O.

The original scope, NativeJob factories/queries/close, restore journal and daily
release/history are production code. Distinct synthetic handles reference one
synthetic Job; the fixture refuses use after positive close. Process creation,
generation attestation, native policy and native APIs remain explicit portable
fixtures. Nothing in this module establishes a native capability or P3-P6 gate.
"""
from contextlib import closing
import copy
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_scope as scope
from sentinel.adaptive import exemption_sync
from sentinel.adaptive import native_job as native
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.native_job import CpuState, JobAccess, NativeJob
from sentinel.exemptions import Exemptions
from tests import test_adaptive_experiment_release_native as release_fixture
from tests import test_adaptive_native_job as job_fixture
from tests.windows import adaptive_scope_launch as launch_module


class _DistinctHandles(job_fixture.Kernel):
    """Every probe has a distinct handle to the retained principal's Job."""
    def __init__(self):
        super().__init__()
        self.live = set()
        self.next_probe = 710
        self.cpu_overrides = {}
        self.on_set = None
        self.accounting = (0,) * 8
        self.membership = [(1, 0, 0, 0, ())] * 100

    def _live(self, handle):
        if handle not in self.live:
            raise AssertionError("synthetic use of missing or positively closed Job handle")

    def CreateJobObjectW(self, attributes, name):
        handle = super().CreateJobObjectW(attributes, name)
        if handle:
            self.live.add(handle)
        return handle

    def DuplicateHandle(self, source_process, source, target_process, output, rights, inherit, options):
        self._live(source)
        result = super().DuplicateHandle(source_process, source, target_process, output, rights, inherit, options)
        if result:
            self.live.add(output._obj.value)
        return result

    def OpenJobObjectW(self, access, inherit, name):
        self._live(job_fixture.RETAINED)
        self.open_handle = self.next_probe
        self.next_probe += 1
        handle = super().OpenJobObjectW(access, inherit, name)
        if handle:
            self.live.add(handle)
        return handle

    def QueryInformationJobObject(self, handle, information_class, output, size, returned):
        self._live(handle)
        result = super().QueryInformationJobObject(handle, information_class, output, size, returned)
        if result and information_class == 15 and handle in self.cpu_overrides:
            output._obj.ControlFlags, output._obj.CpuRate = self.cpu_overrides[handle]
        return result

    def SetInformationJobObject(self, handle, information_class, information, size):
        self._live(handle)
        result = super().SetInformationJobObject(handle, information_class, information, size)
        if self.on_set is not None:
            self.on_set(handle)
        return result

    def CloseHandle(self, handle):
        self._live(handle)
        result = super().CloseHandle(handle)
        if result:
            self.live.remove(handle)
        return result


class ExperimentProbeTests(unittest.TestCase):
    def setUp(self):
        # Composition deliberately avoids repeating the fixture's test cases.
        self.fixture = release_fixture.ExperimentNativeReleaseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.kernel = _DistinctHandles()
        self.fixture.native.kernel = self.kernel
        self.fixture.native.advapi = job_fixture.Advapi(self.kernel)
        self.fixture.native.security = job_fixture.Security(self.kernel.calls)
        self.fixture.native.backend = native._WindowsBackend(kernel=self.kernel,
            advapi=self.fixture.native.advapi, security=self.fixture.native.security)
        original_open = NativeJob.open
        change = patch.object(NativeJob, "open", side_effect=lambda name, nonce, logon_id, **kwargs:
            original_open(name, nonce, logon_id, backend=self.fixture.native.backend, **kwargs))
        self.open_factory = change.start()
        self.addCleanup(change.stop)

    def prepared(self):
        demand, command = self.fixture.admitted()
        # Actual sticky binding, under the original admission POLICY. No grants
        # snapshot or setter authority is replaced by a permissive mock.
        policy = demand._admission._submission_policy
        guard = policy.prepare(self.fixture.guardian.identity.logon_id)
        with policy.hold(guard):
            exemption_sync.bind_policy_locked(Exemptions(self.fixture.db.parent), policy.store)
        with patch.object(launch_module.ScopeLaunch, "create_inert", autospec=True,
                side_effect=self.fixture.create_wrapper):
            owner = scope.ExperimentNativeScope.prepare(demand, command)
        self.fixture.scopes.append(owner)
        self.assertTrue(owner._registered)
        self.assertEqual(owner.job.handle, job_fixture.RETAINED)
        return owner

    def calls(self, name):
        return [call for call in self.kernel.calls if call[0] == name]

    def journal(self, owner):
        with closing(sqlite3.connect(owner.ledger_path)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_experiment_scope_journal").fetchone())

    def assert_charged(self):
        for table, rows in self.fixture.admitted_rows.items():
            self.assertEqual(self.fixture.rows(table), rows)
        self.assertIsNotNone(self.fixture.guardian._handle)

    def test_one_live_two_total_original_open_attempts_and_no_daily_dependency(self):
        owner = self.prepared()
        with patch.object(owner, "_ready", side_effect=AssertionError("probe requested readiness")), \
                patch.object(owner.daily_store, "_connection", side_effect=AssertionError("probe opened daily SQL")):
            first = owner.open_probe()
            self.assertIs(type(first), NativeJob)
            self.assertIs(first.access, JobAccess.CONTROL)
            self.assertEqual((first.name, first.nonce, first.logon_sid),
                (owner.job.name, owner.job.nonce, owner.job.logon_sid))
            self.assertNotEqual(first.handle, owner.job.handle)
            with self.assertRaises(RuntimeError):
                owner.open_probe()
            self.assertEqual(len(self.calls("OpenJobObjectW")), 1)
            owner.close_probe(first)
            second = owner.open_probe()
            self.assertNotEqual(second.handle, first._job.value)
            owner.close_probe(second)
            with self.assertRaises(RuntimeError):
                owner.open_probe()
        self.assertEqual(len(self.calls("OpenJobObjectW")), 2)
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        self.assertFalse(owner.job.closed)
        self.assert_charged()

    def test_principal_cannot_be_unavailable_or_scope_closing_before_probe_open(self):
        owner = self.prepared()
        owner._close_started = True
        with self.assertRaises(RuntimeError):
            owner.open_probe()
        owner._close_started = False
        owner.job.close()
        with self.assertRaises(RuntimeError):
            owner.open_probe()
        self.assertEqual(self.calls("OpenJobObjectW"), [])
        self.assert_charged()

    def test_foreign_same_name_copy_principal_and_dict_are_not_probe_authority(self):
        owner = self.prepared()
        probe = owner.open_probe()
        foreign = NativeJob.open(owner.job_name, owner.creation_nonce,
            owner.guardian.identity.logon_id, access=JobAccess.CONTROL)
        self.addCleanup(foreign.close)
        before = list(self.calls("CloseHandle")), list(self.calls("SetInformationJobObject"))
        for candidate in (foreign, copy.copy(probe), owner.job, {}, SimpleNamespace(handle=probe.handle)):
            for operation in (owner.close_probe, lambda value: owner.restore(through=value)):
                with self.subTest(candidate=type(candidate), operation=operation), self.assertRaises(RuntimeError):
                    operation(candidate)
        self.assertEqual((self.calls("CloseHandle"), self.calls("SetInformationJobObject")), before)
        self.assertFalse(probe.closed)
        self.assertFalse(owner.job.closed)
        owner.close_probe(probe)

    def test_restore_uses_selected_handle_and_both_readbacks_before_actual_ack(self):
        owner = self.prepared()
        self.assertEqual(owner.set_cpu_rate(), CpuState(5, 2500))
        probe = owner.open_probe()
        principal_handle, probe_handle = owner.job.handle, probe.handle
        self.kernel.calls.clear()
        acknowledge = owner.journal.acknowledge_control_locked
        def after_native(conn, observed):
            writes = self.calls("SetInformationJobObject")
            self.assertEqual([value[1] for value in writes], [probe_handle])
            boundary = self.kernel.calls.index(writes[0])
            queried = {value[1] for value in self.kernel.calls[boundary + 1:]
                if value[0] == "QueryInformationJobObject" and value[2] == 15}
            self.assertEqual(queried, {principal_handle, probe_handle})
            return acknowledge(conn, observed)
        def no_sql(handle):
            self.assertEqual(handle, probe_handle)
            self.assertFalse(owner.store.connections)
        self.kernel.on_set = no_sql
        with patch.object(owner.journal, "acknowledge_control_locked", side_effect=after_native), \
                patch.object(owner, "_ready", side_effect=AssertionError("restore requested daily readiness")), \
                patch.object(owner.daily_store, "_connection", side_effect=AssertionError("restore opened daily SQL")):
            self.assertEqual(owner.restore(through=probe), CpuState(0, 0))
        self.assertIsNone(self.journal(owner)["pending_target_json"])
        self.assertFalse(owner.job.closed)
        owner.close_probe(probe)
        self.assert_charged()

    def test_probe_observation_conflict_refuses_restore_write(self):
        owner = self.prepared()
        self.assertEqual(owner.set_cpu_rate(), CpuState(5, 2500))
        probe = owner.open_probe()
        self.kernel.cpu_overrides[probe.handle] = (0, 10000)
        before = list(self.calls("SetInformationJobObject"))
        with self.assertRaises(RuntimeError):
            owner.restore(through=probe)
        self.assertEqual(self.calls("SetInformationJobObject"), before)
        self.kernel.cpu_overrides.clear()
        self.assertEqual(owner.restore(), CpuState(0, 0))
        owner.close_probe(probe)

    def test_principal_post_disable_disagreement_keeps_restore_intent(self):
        owner = self.prepared()
        owner.set_cpu_rate()
        probe = owner.open_probe()
        def principal_stays_capped(handle):
            self.kernel.cpu_overrides[owner.job.handle] = (5, 2500)
        self.kernel.on_set = principal_stays_capped
        with self.assertRaises(RuntimeError):
            owner.restore(through=probe)
        self.assertEqual(json.loads(self.journal(owner)["pending_target_json"]), dict(flags=0, rate_bp=0))
        self.kernel.on_set = None
        self.kernel.cpu_overrides.clear()
        self.assertEqual(owner.restore(through=probe), CpuState(0, 0))
        owner.close_probe(probe)
        self.assert_charged()

    def test_uncertain_selected_disable_retains_same_probe_and_original_intent(self):
        owner = self.prepared()
        owner.set_cpu_rate()
        probe = owner.open_probe()
        original = OSError("synthetic selected Set acknowledgement lost")
        self.kernel.set_exception = original
        with self.assertRaises(OSError) as raised:
            owner.restore(through=probe)
        self.assertIs(raised.exception, original)
        self.assertIn(probe, original._native_job_cleanup)
        self.assertEqual(json.loads(self.journal(owner)["pending_target_json"]), dict(flags=0, rate_bp=0))
        self.kernel.set_exception = None
        writes = len(self.calls("SetInformationJobObject"))
        self.assertEqual(owner.restore(through=probe), CpuState(0, 0))
        self.assertEqual(len(self.calls("SetInformationJobObject")), writes)
        owner.close_probe(probe)

    def test_real_restore_ack_commit_loss_replays_without_repeating_disable(self):
        owner = self.prepared()
        owner.set_cpu_rate()
        probe = owner.open_probe()
        armed = {"value": False, "failed": False}
        original = OSError("synthetic restore COMMIT acknowledgement lost")
        class AckLost(sqlite3.Connection):
            def commit(connection):
                super().commit()
                if armed["value"] and not armed["failed"]:
                    armed["failed"] = True
                    raise original
        connect = sqlite3.connect
        def isolated_connect(path, *args, **kwargs):
            if Path(path).resolve() == owner.ledger_path.resolve():
                kwargs["factory"] = AckLost
            return connect(path, *args, **kwargs)
        acknowledge = owner.journal.acknowledge_control_locked
        def arm(conn, observed):
            result = acknowledge(conn, observed)
            armed["value"] = True
            return result
        with patch.object(scope.sqlite3, "connect", side_effect=isolated_connect), \
                patch.object(owner.journal, "acknowledge_control_locked", side_effect=arm), \
                self.assertRaises(OSError) as raised:
            owner.restore(through=probe)
        self.assertIs(raised.exception, original)
        self.assertTrue(armed["failed"])
        self.assertIsNone(self.journal(owner)["pending_target_json"])
        writes = len(self.calls("SetInformationJobObject"))
        self.assertEqual(owner.restore(through=probe), CpuState(0, 0))
        self.assertEqual(len(self.calls("SetInformationJobObject")), writes)
        owner.close_probe(probe)

    def test_original_positive_probe_close_is_idempotent_and_keeps_capacity(self):
        owner = self.prepared()
        probe = owner.open_probe()
        handle = probe.handle
        owner.close_probe(probe)
        owner.close_probe(probe)
        self.assertTrue(probe.closed)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", handle)), 1)
        self.assertFalse(owner.job.closed)
        self.assertIsNone(owner.completion)
        self.assert_charged()

    def test_known_false_probe_close_retries_only_same_owner(self):
        owner = self.prepared()
        probe = owner.open_probe()
        handle = probe.handle
        self.kernel.close_failures.add(handle)
        with self.assertRaises(native.NativeJobError):
            owner.close_probe(probe)
        self.assertFalse(probe.closed)
        with self.assertRaises(RuntimeError):
            owner.open_probe()
        self.assertEqual(len(self.calls("OpenJobObjectW")), 1)
        self.kernel.close_failures.remove(handle)
        owner.close_probe(probe)
        self.assertTrue(probe.closed)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", handle)), 2)
        self.assert_charged()

    def test_unknown_close_never_repeats_and_principal_restore_still_works(self):
        owner = self.prepared()
        owner.set_cpu_rate()
        probe = owner.open_probe()
        handle = probe.handle
        original = OSError("synthetic probe CloseHandle outcome unknown")
        self.kernel.close_exceptions[handle] = original
        with self.assertRaises(OSError) as raised:
            owner.close_probe(probe)
        self.assertIs(raised.exception, original)
        self.assertEqual(owner.restore(), CpuState(0, 0))
        for operation in (lambda: owner.close_probe(probe), owner.open_probe,
                owner.set_cpu_rate, owner.close_native):
            with self.subTest(operation=operation), self.assertRaises(RuntimeError):
                operation()
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", handle)), 1)
        self.assertEqual(len(self.calls("OpenJobObjectW")), 1)
        self.assertFalse(owner.job.closed)
        self.assertIsNone(owner.completion)
        self.assert_charged()

    def test_failed_open_retains_original_factory_owner_even_after_positive_close(self):
        owner = self.prepared()
        original = RuntimeError("synthetic opened probe security check rejected")
        security = self.fixture.native.security
        security.failure, security.fail_handle = original, self.kernel.next_probe
        with self.assertRaises(RuntimeError) as raised:
            owner.open_probe()
        self.assertIs(raised.exception, original)
        candidates = original._native_job_initialization_owners
        self.assertEqual(len(candidates), 1)
        self.assertIs(type(candidates[0]), NativeJob)
        self.assertIs(candidates[0].access, JobAccess.CONTROL)
        self.assertTrue(candidates[0].closed)
        security.failure = None
        completion = owner.close_native()
        self.assertEqual(completion.snapshot()["probe_custody"], [{"ordinal": 1, "outcome": "failed_closed"}])
        self.fixture.release_completion(owner, completion)

    def test_failed_open_known_close_false_resumes_original_before_principal(self):
        owner = self.prepared()
        handle = self.kernel.next_probe
        security = self.fixture.native.security
        security.failure, security.fail_handle = RuntimeError("synthetic probe verification failed"), handle
        self.kernel.close_failures.add(handle)
        with self.assertRaises(RuntimeError) as raised:
            owner.open_probe()
        partial = raised.exception._native_job_initialization_owners[0]
        self.assertFalse(partial.closed)
        security.failure = None
        self.kernel.close_failures.remove(handle)
        completion = owner.close_native()
        self.assertTrue(partial.closed)
        closes = self.calls("CloseHandle")
        self.assertLess(max(index for index, call in enumerate(closes) if call[1] == handle),
            closes.index(("CloseHandle", job_fixture.RETAINED)))
        self.assertEqual(completion.snapshot()["probe_custody"], [{"ordinal": 1, "outcome": "failed_closed"}])
        self.fixture.release_completion(owner, completion)

    def test_factory_error_graph_extra_or_duplicate_owner_rejects_completion_replay(self):
        owner = self.prepared()
        security = self.fixture.native.security
        original = RuntimeError("synthetic original failed probe")
        security.failure, security.fail_handle = original, None
        with self.assertRaises(RuntimeError) as first:
            owner.open_probe()
        self.assertIs(first.exception, original)
        accounted = original._native_job_initialization_owners
        self.assertEqual(len(accounted), 1)
        # Obtain a second genuine factory owner while the principal is retained,
        # but outside this scope's original attempt graph. Its exception is
        # initially separate so valid original completion can be produced.
        foreign_error = RuntimeError("synthetic unrelated same-name failed open")
        security.failure = foreign_error
        with self.assertRaises(RuntimeError) as foreign:
            NativeJob.open(owner.job_name, owner.creation_nonce,
                owner.guardian.identity.logon_id, access=JobAccess.CONTROL)
        self.assertIs(foreign.exception, foreign_error)
        unaccounted = foreign_error._native_job_initialization_owners[0]
        self.assertTrue(unaccounted.closed)
        self.assertIsNot(unaccounted, accounted[0])
        security.failure = None
        completion = owner.close_native()
        snapshot = completion.snapshot()
        calls = list(self.kernel.calls)
        for extra in (accounted[0], unaccounted):
            try:
                original._native_job_initialization_owners = (*accounted, extra)
                for operation in (completion.snapshot, owner.close_native):
                    with self.subTest(extra=extra, operation=operation), self.assertRaises(RuntimeError):
                        operation()
            finally:
                original._native_job_initialization_owners = accounted
        self.assertEqual(self.kernel.calls, calls)
        self.assertEqual(completion.snapshot(), snapshot)
        self.fixture.release_completion(owner, completion)

    def test_same_error_reused_by_two_original_failed_opens_keeps_both_owners(self):
        owner = self.prepared()
        original = RuntimeError("synthetic shared probe factory rejection")
        security = self.fixture.native.security
        security.failure, security.fail_handle = original, None
        for ordinal in (1, 2):
            with self.assertRaises(RuntimeError) as raised:
                owner.open_probe()
            self.assertIs(raised.exception, original)
            self.assertEqual(len(original._native_job_initialization_owners), ordinal)
            self.assertTrue(all(value.closed for value in original._native_job_initialization_owners))
        first, second = original._native_job_initialization_owners
        self.assertIsNot(first, second)
        self.assertNotEqual(first._job.value, second._job.value)
        security.failure = None
        with self.assertRaises(RuntimeError):
            owner.open_probe()
        self.assertEqual(len(self.calls("OpenJobObjectW")), 2)
        completion = owner.close_native()
        self.assertEqual(completion.snapshot()["probe_custody"], [
            dict(ordinal=1, outcome="failed_closed"), dict(ordinal=2, outcome="failed_closed")])
        self.fixture.release_completion(owner, completion)

    def test_unknown_open_cannot_be_replaced_or_completed(self):
        owner = self.prepared()
        original = OSError("synthetic OpenJobObjectW outcome unknown")
        self.kernel.open_exception = original
        with self.assertRaises(OSError) as raised:
            owner.open_probe()
        self.assertIs(raised.exception, original)
        partial = original._native_job_initialization_owners[0]
        self.assertFalse(partial.closed)
        self.assertEqual(partial._job.state, "allocation_unknown")
        self.kernel.open_exception = None
        for operation in (owner.open_probe, owner.close_native):
            with self.subTest(operation=operation), self.assertRaises(RuntimeError):
                operation()
        self.assertEqual(len(self.calls("OpenJobObjectW")), 1)
        self.assertFalse(owner.job.closed)
        self.assertIsNone(owner.completion)
        self.assert_charged()

    def test_missing_original_factory_evidence_never_claims_absence(self):
        owner = self.prepared()
        original = RuntimeError("synthetic factory interrupted before supplying custody")
        with patch.object(NativeJob, "open", side_effect=original), self.assertRaises(RuntimeError) as raised:
            owner.open_probe()
        self.assertIs(raised.exception, original)
        for operation in (owner.open_probe, owner.close_native):
            with self.subTest(operation=operation), self.assertRaises(RuntimeError):
                operation()
        self.assertEqual(self.calls("OpenJobObjectW"), [])
        self.assertFalse(owner.job.closed)
        self.assertIsNone(owner.completion)
        self.assert_charged()

    def test_close_native_settles_probe_before_principal_and_returns_version_two(self):
        owner = self.prepared()
        probe = owner.open_probe()
        handle = probe.handle
        self.kernel.close_failures.add(handle)
        with self.assertRaises(native.NativeJobError):
            owner.close_native()
        self.assertFalse(owner.job.closed)
        self.assertIsNone(owner.completion)
        self.assert_charged()
        self.kernel.close_failures.remove(handle)
        completion = owner.close_native()
        self.assertTrue(probe.closed)
        self.assertTrue(owner.job.closed)
        snapshot = completion.snapshot()
        self.assertEqual(snapshot["schema_version"], 2)
        self.assertEqual(snapshot["disposition"], "NEVER_LAUNCHED")
        self.assertEqual(snapshot["probe_custody"], [{"ordinal": 1, "outcome": "opened_closed"}])
        closes = self.calls("CloseHandle")
        self.assertLess(max(index for index, call in enumerate(closes) if call[1] == handle),
            closes.index(("CloseHandle", job_fixture.RETAINED)))
        self.assertIs(owner.close_native(), completion)
        self.fixture.release_completion(owner, completion)

    def test_finished_reopened_restore_completion_passes_actual_release_history(self):
        owner = self.prepared()
        self.assertIs(owner.launch_once(), self.fixture.root)
        owner.set_cpu_rate()
        first = owner.open_probe()
        first_handle = first.handle
        owner.close_probe(first)
        reopened = owner.open_probe()
        reopened_handle = reopened.handle
        self.assertNotEqual(first_handle, reopened_handle)
        self.assertEqual(owner.restore(through=reopened), CpuState(0, 0))
        owner.close_probe(reopened)
        self.fixture.root_backend.state = IdentityStatus.DEAD
        self.kernel.accounting = (0, 0, 0, 0, 0, 1, 0, 1)
        completion = owner.close_native()
        snapshot = completion.snapshot()
        self.assertEqual((snapshot["schema_version"], snapshot["disposition"]), (2, "FINISHED"))
        self.assertEqual(snapshot["probe_custody"], [dict(ordinal=1, outcome="opened_closed"),
            dict(ordinal=2, outcome="opened_closed")])
        self.assertIn(reopened_handle, [call[1] for call in self.calls("SetInformationJobObject") if call[3] == 0])
        self.fixture.release_completion(owner, completion)

    def test_completion_replay_revalidates_original_closed_probe_not_only_summary(self):
        owner = self.prepared()
        probe = owner.open_probe()
        completion = owner.close_native()
        snapshot = completion.snapshot()
        native_calls = list(self.kernel.calls)
        # Each corrupts the original owner while leaving the serialized summary
        # and its digest unchanged. Returning the stored receipt is insufficient.
        for target, field, changed in ((probe, "name", probe.name + "-replacement"),
                (probe, "access", JobAccess.QUERY), (probe._job, "state", "owned")):
            before = getattr(target, field)
            try:
                setattr(target, field, changed)
                for operation in (completion.snapshot, owner.close_native):
                    with self.subTest(field=field, operation=operation), self.assertRaises(RuntimeError):
                        operation()
            finally:
                setattr(target, field, before)
        self.assertEqual(self.kernel.calls, native_calls)
        self.assertEqual(completion.snapshot(), snapshot)
        self.fixture.release_completion(owner, completion)

    def test_no_probe_completion_preserves_exact_version_one_shape(self):
        owner = self.prepared()
        completion = owner.close_native()
        snapshot = completion.snapshot()
        self.assertEqual(snapshot["schema_version"], 1)
        self.assertNotIn("probe_custody", snapshot)
        self.fixture.release_completion(owner, completion)


if __name__ == "__main__":
    unittest.main()
