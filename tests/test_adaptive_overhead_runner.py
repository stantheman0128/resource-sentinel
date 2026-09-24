"""Synthetic reducer and fail-closed interface tests, never native P4 evidence."""
from contextlib import closing
import ctypes as C
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from tests.windows import adaptive_cost_probe as cost
from tests.windows import adaptive_overhead_native as native
from tests.windows import adaptive_overhead_runner as runner
from tests.test_adaptive_daily_monitor import DailyMonitorFixture
from tests.test_adaptive_decision import profile as decision_profile


LOGON = "S-1-5-5-10-20"


def identity(pid):
    return ProcessIdentity(pid, 100000 + pid, LOGON)


def reading(pid, cpu=100, private=20, handles=3, peak=None):
    return SimpleNamespace(identity=identity(pid), cpu_100ns=cpu,
        private_bytes=private, handles=handles,
        peak_private_bytes=private if peak is None else peak)


def audit(**changes):
    values = dict(identity=identity(2), scope_nonce="a" * 32, sequence=1,
        observed_tick=100, installed_tick=1, calls=0, restrictive_calls=0)
    values.update(changes)
    return runner.NativeSetObservation(**values)


class NativeCostLayoutTests(unittest.TestCase):
    def test_documented_memory_layout_at_both_pointer_widths(self):
        names = [name for name, _ in cost._MemoryCountersEx._fields_]
        expected = ["cb", "PageFaultCount", "PeakWorkingSetSize", "WorkingSetSize",
            "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
            "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage"]
        self.assertEqual(names, expected)
        for pointer, size, private_offset, peak_offset in (
                (C.c_uint32, 44, 40, 36), (C.c_uint64, 80, 72, 64)):
            with self.subTest(size=size):
                class Layout(C.Structure):
                    _fields_ = [(name, C.c_uint32 if i < 2 else pointer)
                                for i, name in enumerate(names)]
                self.assertEqual(C.sizeof(Layout), size)
                self.assertEqual(Layout.PrivateUsage.offset, private_offset)
                self.assertEqual(Layout.PeakPagefileUsage.offset, peak_offset)
                for i, name in enumerate(names[2:]):
                    self.assertEqual(getattr(Layout, name).offset, 8 + i * C.sizeof(pointer))

    def test_native_struct_has_exact_host_abi(self):
        width = C.sizeof(C.c_size_t)
        self.assertEqual(C.sizeof(cost._MemoryCountersEx), 8 + 9 * width)
        self.assertEqual(cost._MemoryCountersEx.PagefileUsage.offset, 8 + 6 * width)
        self.assertEqual(cost._MemoryCountersEx.PeakPagefileUsage.offset, 8 + 7 * width)
        self.assertEqual(cost._MemoryCountersEx.PrivateUsage.offset, 8 + 8 * width)


class P4ReducerTests(unittest.TestCase):
    def setUp(self):
        self.roles = {identity(1): frozenset(("helper",)), identity(2): frozenset(("guardian",)),
                      identity(3): frozenset(("waiting_wrapper",))}

    def test_exact_identity_join_ignores_snapshot_order(self):
        result = runner.process_endpoints(self.roles,
            [reading(1), reading(2), reading(3)],
            [reading(3, 120), reading(1, 130), reading(2, 150)])
        self.assertEqual([row["cpu_end_100ns"] for row in result], [130, 150, 120])
        self.assertEqual(result[0]["identity"], identity(1).to_dict())

    def test_reused_pid_different_creation_time_refuses_cpu_splice(self):
        last = [reading(1), reading(2), reading(3)]
        last[0].identity = ProcessIdentity(1, 999999, LOGON)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "identity_changed"):
            runner.process_endpoints(self.roles, [reading(1), reading(2), reading(3)], last)

    def test_duplicate_reading_is_not_complete_coverage(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "identity_changed"):
            runner.process_endpoints(self.roles, [reading(1), reading(2), reading(3)],
                                     [reading(1), reading(1), reading(3)])

    def test_reversed_cpu_endpoint_is_not_zero_cost(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "counter_reversed"):
            runner.process_endpoints(self.roles, [reading(1), reading(2), reading(3)],
                                     [reading(1, 99), reading(2), reading(3)])

    def test_boolean_cpu_is_not_numeric_evidence(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "counter_invalid"):
            runner.process_endpoints(self.roles, [reading(1, True), reading(2), reading(3)],
                                     [reading(1), reading(2), reading(3)])

    def test_private_totals_use_actual_lifetime_peak_without_baseline_discount(self):
        self.assertEqual(runner.memory_totals(self.roles,
            [reading(1, private=20, peak=80), reading(2, private=30, peak=50),
             reading(3, private=40, peak=90)]), (130, 90, 130, 220, [80, 50, 90]))

    def test_each_wrapper_limit_uses_max_not_sum(self):
        roles = dict(self.roles)
        roles[identity(4)] = frozenset(("waiting_wrapper",))
        self.assertEqual(runner.memory_totals(roles,
            [reading(1), reading(2), reading(3, private=30), reading(4, private=50)]),
            (40, 50, 40, 120, [20, 20, 30, 50]))

    def test_cohosted_observers_charged_once_and_roles_preserved(self):
        roles = dict(self.roles)
        roles[identity(4)] = frozenset(("supervisor", "accounting_keeper", "daily_activation"))
        rows = [reading(1), reading(2), reading(3), reading(4, private=70)]
        self.assertEqual(runner.memory_totals(roles, rows),
            (40, 20, 110, 130, [20, 20, 20, 70]))
        endpoints = runner.process_endpoints(roles, rows, rows)
        self.assertEqual(endpoints[-1]["roles"],
            ["accounting_keeper", "daily_activation", "supervisor"])

    def test_peak_vector_uses_exact_process_inventory_order(self):
        rows = [reading(3, private=3), reading(1, private=1), reading(2, private=2)]
        self.assertEqual(runner.memory_totals(self.roles, rows)[-1], [1, 2, 3])

    def test_peak_below_current_refuses_inconsistent_sample(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "peak_inconsistent"):
            runner.memory_totals(self.roles,
                [reading(1, private=30, peak=20), reading(2), reading(3)])

    def test_missing_monitor_is_not_zero_memory(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_incomplete"):
            runner.memory_totals(self.roles, [reading(1), reading(2)])

    def test_missing_cases_remain_unverified_zero(self):
        values = dict.fromkeys(runner.CASE_KEYS, 0)
        delta = dict(values, membership_added=3, subtraction_zero_samples=4)
        runner.add_cases(values, delta)
        self.assertEqual(values["membership_added"], 3)
        self.assertEqual(values["inaccessible_identity"], 0)
        self.assertEqual(values["member_scan_timeout"], 0)

    def test_case_schema_cannot_omit_unverified_dimensions(self):
        values = dict.fromkeys(runner.CASE_KEYS, 0)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "schema_invalid"):
            runner.add_cases(values, {"membership_added": 1})

    def test_case_boolean_is_not_observed_count(self):
        values = dict.fromkeys(runner.CASE_KEYS, 0)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "case_invalid"):
            runner.add_cases(values, dict(values, inaccessible_identity=True))


class MonitorInventoryTests(unittest.TestCase):
    def build(self, *, cohost=True):
        fixture = DailyMonitorFixture()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        monitor = fixture.capture()
        keeper = monitor.assert_original()
        owners = []
        for pid in (1, 2, 3, 4):
            owner = VerifiedProcess(None, None, identity(pid))
            owner.observe = Mock(return_value=SimpleNamespace(identity=owner.identity,
                                                               status=IdentityStatus.ALIVE))
            owners.append(owner)
        helper, guardian, wrapper, supervisor = owners
        if cohost:
            supervisor = keeper
        session = SimpleNamespace(helper=helper, guardian=guardian, wrappers=(wrapper,),
            daily_monitor=monitor,
            helper_host=SimpleNamespace(process=helper, parent_process=supervisor),
            monitor_processes=(("helper", helper), ("guardian", guardian),
                ("waiting_wrapper", wrapper), ("supervisor", supervisor),
                ("accounting_keeper", keeper), ("daily_activation", keeper)))
        session.fixture = fixture  # Explicit test-only origin for real SQL release below.
        return session, SimpleNamespace(logon_id=LOGON)

    def test_original_cohosted_roles_keep_one_cpu_witness(self):
        session, context = self.build()
        witnesses, roles, monitor, keeper = runner.monitor_inventory(session, context, 1)
        self.assertEqual(len(witnesses), 4)
        self.assertEqual(roles[session.daily_monitor.identity], runner.COHOST_ROLES)
        self.assertIs(monitor, session.daily_monitor)
        self.assertIs(keeper, monitor.assert_original())

    def test_distinct_original_supervisor_is_charged_separately(self):
        session, context = self.build(cohost=False)
        witnesses, roles, unused_monitor, unused_keeper = runner.monitor_inventory(session, context, 1)
        self.assertEqual(len(witnesses), 5)
        self.assertEqual(roles[identity(4)], frozenset(("supervisor",)))
        self.assertEqual(roles[session.daily_monitor.identity],
            frozenset(("accounting_keeper", "daily_activation")))

    def test_absent_or_untyped_monitor_is_not_authenticated_custody(self):
        session, context = self.build()
        original = session.daily_monitor
        for value in (None, SimpleNamespace(assert_original=original.assert_original), {}):
            session.daily_monitor = value
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(runner.NativeRunBlocked, "authenticated_daily_monitor_required"):
                    runner.monitor_inventory(session, context, 1)

    def test_live_same_logon_supervisor_cannot_replace_authenticated_keeper(self):
        session, context = self.build(cohost=False)
        session.monitor_processes = (*session.monitor_processes[:4],
            ("accounting_keeper", session.helper_host.parent_process),
            ("daily_activation", session.helper_host.parent_process))
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_incomplete"):
            runner.monitor_inventory(session, context, 1)

    def test_same_identity_alias_must_be_same_original_handle_owner(self):
        session, context = self.build()
        original = session.daily_monitor.assert_original()
        other = VerifiedProcess(None, None, original.identity)
        other.observe = original.observe
        # Merely updating the supervisor member as well cannot legitimize a
        # same-identity, independently reopened peer as the original keeper.
        session.helper_host.parent_process = other
        session.monitor_processes = (*session.monitor_processes[:3],
            ("supervisor", other), *session.monitor_processes[4:])
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_incomplete"):
            runner.monitor_inventory(session, context, 1)

    def test_duplicate_role_remains_invalid_even_for_authenticated_witness(self):
        session, context = self.build()
        session.monitor_processes = (*session.monitor_processes[:-1], session.monitor_processes[-2])
        with self.assertRaisesRegex(runner.NativeRunBlocked, "role_duplicate"):
            runner.monitor_inventory(session, context, 1)

    def test_missing_keeper_is_not_complete_monitoring(self):
        session, context = self.build()
        session.monitor_processes = session.monitor_processes[:-1]
        with self.assertRaisesRegex(runner.NativeRunBlocked, "roles_incomplete"):
            runner.monitor_inventory(session, context, 1)

    def test_helper_cannot_be_relabeled_as_accounting_keeper(self):
        session, context = self.build()
        session.monitor_processes = (*session.monitor_processes[:4],
            ("accounting_keeper", session.helper), session.monitor_processes[-1])
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_incomplete"):
            runner.monitor_inventory(session, context, 1)

    def test_reopened_parent_with_same_identity_is_not_original_witness(self):
        session, context = self.build()
        original = session.helper_host.parent_process
        other = VerifiedProcess(None, None, original.identity)
        other.observe = original.observe
        session.monitor_processes = (*session.monitor_processes[:3],
            ("supervisor", other), *session.monitor_processes[4:])
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_incomplete"):
            runner.monitor_inventory(session, context, 1)

    def test_continuous_check_keeps_the_open_sessions_original_monitor(self):
        session, context = self.build()
        runner.monitor_inventory(session, context, 1)
        session.assert_daily_coverage = lambda: None
        producer = object.__new__(runner.P4Producer)
        producer._monitor_pin = (session, session.daily_monitor, session.daily_monitor.assert_original())
        producer._covered(session)
        session.daily_monitor = SimpleNamespace(assert_original=producer._monitor_pin[1].assert_original)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "original_daily_monitor_changed"):
            producer._covered(session)

    def test_open_cannot_replace_validated_monitor_through_changing_property(self):
        base, context = self.build()
        original = base.daily_monitor
        keeper = original.assert_original()
        base.helper = base.fixture.caller
        base.helper_host.process = base.helper
        base.monitor_processes = (("helper", base.helper), *base.monitor_processes[1:])
        base.jobs = (("unused-before-native", object()),)
        profile = decision_profile()
        base.profile_revision, base.context = runner.profile_revision(profile), context
        base.scope_nonce = "a" * 32
        base.log_directory = base.fixture.fixture.scope / "runtime-logs"
        base.log_directory.mkdir()
        for name in ("assert_daily_coverage", "read_guardian_set_audit", "read_resident_telemetry",
                     "enter_idle", "enter_stress", "prepare_wrapper_trial", "retire"):
            setattr(base, name, lambda: None)

        class ChangingSession:
            reads = 0

            @property
            def daily_monitor(self):
                self.reads += 1
                return original if self.reads == 1 else SimpleNamespace(assert_original=lambda: keeper)

            def __getattr__(self, name):
                return getattr(base, name)

        session = ChangingSession()
        producer = object.__new__(runner.P4Producer)
        producer.directory, producer.profile, producer.context = base.fixture.fixture.scope, profile, context
        producer._monitor_pin, producer.local_owners = None, []
        producer.coverage = SimpleNamespace(open_overhead_session=lambda **unused: session)
        with patch.object(native, "NativeCostProbe", side_effect=AssertionError("probe initialized")):
            with self.assertRaisesRegex(runner.NativeRunBlocked, "original_daily_monitor_changed"):
                producer._open(1, "scale-1")
        self.assertIs(producer._monitor_pin[1], original)
        self.assertIs(producer._monitor_pin[2], keeper)

    def test_retirement_boolean_cannot_hide_an_unclosed_daily_monitor(self):
        session, context = self.build()
        runner.monitor_inventory(session, context, 1)
        session.assert_daily_coverage = lambda: None
        session.retire = Mock()
        session.custody_pending = False
        producer = object.__new__(runner.P4Producer)
        producer._monitor_pin = (session, session.daily_monitor, session.daily_monitor.assert_original())
        producer.active, producer.local_owners = session, []
        with self.assertRaisesRegex(runner.NativeRunBlocked, "daily_monitor_retirement_unverified"):
            producer._retire(session, SimpleNamespace(close=Mock()), SimpleNamespace(close=Mock()))
        self.assertIs(producer.active, session)
        self.assertTrue(session.daily_monitor.custody_pending)

    def test_retirement_keeps_monitor_receipt_after_real_daily_release(self):
        session, context = self.build()
        runner.monitor_inventory(session, context, 1)
        session.assert_daily_coverage = lambda: None
        session.custody_pending = True
        producer = object.__new__(runner.P4Producer)
        producer._monitor_pin = (session, session.daily_monitor, session.daily_monitor.assert_original())
        producer.active, producer.local_owners = session, []

        def retire():
            session.daily_monitor.close()
            result = session.fixture.release_original_demand()
            self.assertTrue(result["released"])
            session.custody_pending = False

        session.retire = retire
        producer._retire(session, SimpleNamespace(close=Mock()), SimpleNamespace(close=Mock()))
        self.assertIsNone(producer.active)
        self.assertIsNone(producer._monitor_pin)
        self.assertTrue(session.fixture.demand._closed)
        self.assertFalse(session.daily_monitor.custody_pending)


class NativeAuditTests(unittest.TestCase):
    def verify(self, value, previous=None, now=101):
        return runner.validate_audit(value, previous, guardian=identity(2),
            nonce="a" * 32, now=now, maximum_age=30)

    def test_authenticated_actual_zero_counter_is_accepted(self):
        self.assertEqual(self.verify(audit()).calls, 0)

    def test_empty_list_or_boolean_is_not_zero_set_observation(self):
        for value in ([], True, None, {"calls": 0}):
            with self.subTest(value=value), self.assertRaises(runner.NativeRunBlocked):
                self.verify(value)

    def test_other_guardian_or_scope_cannot_attest_zero_set(self):
        for value in (audit(identity=identity(5)), audit(scope_nonce="b" * 32)):
            with self.subTest(value=value), self.assertRaisesRegex(
                    runner.NativeRunBlocked, "binding_invalid"):
                self.verify(value)

    def test_same_sequence_replay_is_rejected(self):
        with self.assertRaisesRegex(runner.NativeRunBlocked, "replayed"):
            self.verify(audit(), audit())

    def test_reinstalled_or_rolled_back_counter_is_rejected(self):
        for value in (audit(sequence=2, installed_tick=2),
                      audit(sequence=2, calls=0)):
            with self.subTest(value=value), self.assertRaisesRegex(
                    runner.NativeRunBlocked, "replayed"):
                self.verify(value, audit(calls=1))

    def test_stale_or_future_timestamp_cannot_prove_zero_writes(self):
        for value in (audit(observed_tick=60), audit(observed_tick=102)):
            with self.subTest(value=value), self.assertRaises(runner.NativeRunBlocked):
                self.verify(value)

    def test_recorded_set_count_is_not_silently_zeroed(self):
        result = self.verify(audit(calls=3, restrictive_calls=2))
        self.assertEqual((result.calls, result.restrictive_calls), (3, 2))


class NativeSourceBoundaryTests(unittest.TestCase):
    def test_real_boundary_interposer_counts_attempt_without_forwarding_set(self):
        original = Mock(spec=[])
        kernel = SimpleNamespace(SetInformationJobObject=original)
        interposer = native._SetAudit(kernel)
        interposer.install()
        with self.assertRaisesRegex(native.NativeOverheadError, "set_attempted"):
            kernel.SetInformationJobObject(10, 15, object(), 8)
        self.assertEqual(interposer.calls, 1)
        original.assert_not_called()
        interposer.close()
        self.assertIs(kernel.SetInformationJobObject, original)

    def test_replaced_audit_is_unknown_and_does_not_overwrite_foreign_writer(self):
        kernel = SimpleNamespace(SetInformationJobObject=Mock(spec=[]))
        interposer = native._SetAudit(kernel)
        interposer.install()
        foreign = Mock()
        kernel.SetInformationJobObject = foreign
        with self.assertRaisesRegex(native.NativeOverheadError, "audit_changed"):
            interposer.close()
        self.assertIs(kernel.SetInformationJobObject, foreign)

    def test_second_audit_install_is_not_silently_stacked(self):
        kernel = SimpleNamespace(SetInformationJobObject=Mock(spec=[]))
        original = native._SetAudit(kernel)
        original.install()
        with self.assertRaisesRegex(native.NativeOverheadError, "already_installed"):
            native._SetAudit(kernel)
        original.close()

    def test_prepared_but_uninstalled_audit_cannot_verify_zero_sets(self):
        original = Mock(spec=[])
        kernel = SimpleNamespace(SetInformationJobObject=original)
        interposer = native._SetAudit(kernel)
        with self.assertRaisesRegex(native.NativeOverheadError, "audit_changed"):
            interposer.verify()
        interposer.close()
        self.assertIs(kernel.SetInformationJobObject, original)

    def test_retained_prepared_owner_cleans_interrupted_install_publication(self):
        original = Mock(spec=[])
        kernel = SimpleNamespace(SetInformationJobObject=original)
        interposer = native._SetAudit(kernel)
        # The real sampler retains this owner before install(). Model the cut
        # after assignment and before the installed flag is published.
        kernel.SetInformationJobObject = interposer.interposer
        self.assertFalse(interposer.installed)
        interposer.close()
        self.assertIs(kernel.SetInformationJobObject, original)

    def test_borrowed_probe_close_never_closes_process_owner(self):
        probe = object.__new__(native.NativeCostProbe)
        owner = SimpleNamespace(close=Mock())
        probe._witnesses = [(owner, identity(1))]
        probe.close()
        owner.close.assert_not_called()

    def test_native_reading_peak_does_not_accept_impossible_lower_number(self):
        with self.assertRaisesRegex(native.NativeOverheadError, "reading_invalid"):
            native.NativeProcessReading(identity(1), 100, 200, 3, 100)

    def test_native_reading_rejects_boolean_measurements(self):
        with self.assertRaisesRegex(native.NativeOverheadError, "reading_invalid"):
            native.NativeProcessReading(identity(1), True, 20, 3, 30)


class P4BoundaryTests(unittest.TestCase):
    def test_missing_daily_bridge_refuses_before_native_setup_or_files(self):
        coverage = SimpleNamespace()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "absent"
            with self.assertRaisesRegex(runner.NativeRunBlocked, "daily_cohort_unavailable"):
                runner.produce_p4(coverage, target, None, None)
            self.assertFalse(target.exists())

    def test_no_duration_shortcut_is_exposed(self):
        import inspect
        self.assertEqual(runner.SCALE_SECONDS, 600)
        self.assertEqual(runner.LEAK_SECONDS, 3600)
        self.assertEqual(runner.SCALES, (1, 10, 50))
        self.assertEqual(set(inspect.signature(runner.produce_p4).parameters),
                         {"coverage", "evidence_directory", "context", "profile"})

    def test_boolean_coverage_is_not_authority(self):
        producer = object.__new__(runner.P4Producer)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "coverage_contract_invalid"):
            producer._covered(SimpleNamespace(assert_daily_coverage=lambda: True))

    def test_custody_retirement_does_not_close_originals_when_sampling_close_fails(self):
        producer = object.__new__(runner.P4Producer)
        session = SimpleNamespace(assert_daily_coverage=lambda: None, retire=Mock())
        sampler = SimpleNamespace(close=Mock(side_effect=RuntimeError("uncertain")))
        probe = SimpleNamespace(close=Mock())
        with self.assertRaisesRegex(RuntimeError, "uncertain"):
            producer._retire(session, probe, sampler)
        session.retire.assert_not_called()
        probe.close.assert_not_called()

    def test_pending_open_failure_retains_exact_coverage(self):
        producer = object.__new__(runner.P4Producer)
        producer.active = None
        producer.pending_open = True
        producer.coverage = SimpleNamespace(pending_admissions=[])
        producer.local_owners = [object()]
        producer._scale = Mock(side_effect=RuntimeError("create acknowledgement lost"))
        with self.assertRaises(runner.OverheadUnsettled) as caught:
            producer.run()
        self.assertIs(caught.exception.coverage, producer.coverage)
        self.assertIs(caught.exception.local_owners[0], producer.local_owners[0])

    def test_interrupt_retains_owner_without_swallowing_interrupt(self):
        producer = object.__new__(runner.P4Producer)
        producer.active = object()
        producer.pending_open = False
        producer.coverage = SimpleNamespace(pending_admissions=[])
        producer.local_owners = []
        interruption = KeyboardInterrupt()
        producer._scale = Mock(side_effect=interruption)
        with self.assertRaises(KeyboardInterrupt) as caught:
            producer.run()
        self.assertIs(caught.exception, interruption)
        self.assertIs(caught.exception.overhead_owner.session, producer.active)

    def test_actual_runtime_footprint_is_read_only_and_excludes_evidence_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "state.db"
            logs = root / "logs"
            logs.mkdir()
            # sqlite3's connection context commits/rolls back, but does not
            # close the handle. Explicit closing prevents a Windows file lock
            # from this setup connection surviving TemporaryDirectory cleanup.
            with closing(sqlite3.connect(database)) as conn:
                with conn:
                    conn.execute("CREATE TABLE sample(id INTEGER)")
                    conn.executemany("INSERT INTO sample VALUES (?)", [(1,), (2,)])
            (logs / "runtime.log").write_bytes(b"12345")
            (root / "large-producer-trace.jsonl").write_bytes(b"x" * 1000)
            before = database.read_bytes()
            self.assertEqual(runner.read_runtime_footprint(database, logs), (2, 5))
            self.assertEqual(database.read_bytes(), before)

    def test_trace_flush_failure_preserves_original_interrupt_and_cleanup_owner(self):
        interruption = KeyboardInterrupt()
        cleanup = OSError("flush failed")
        trace = SimpleNamespace(close=Mock(side_effect=cleanup))
        with self.assertRaises(KeyboardInterrupt) as caught:
            try:
                raise interruption
            finally:
                runner.close_trace_preserving_primary(trace)
        self.assertIs(caught.exception, interruption)
        self.assertIs(interruption.overhead_trace, trace)
        self.assertIs(interruption.overhead_trace_cleanup, cleanup)

    def test_trace_flush_failure_without_primary_retains_stream_owner(self):
        cleanup = OSError("fsync failed")
        trace = SimpleNamespace(close=Mock(side_effect=cleanup))
        with self.assertRaises(OSError) as caught:
            runner.close_trace_preserving_primary(trace)
        self.assertIs(caught.exception.overhead_trace, trace)

    def test_interrupt_during_trace_cleanup_is_not_swallowed_by_ordinary_primary(self):
        primary = RuntimeError("query failed")
        interruption = KeyboardInterrupt()
        trace = SimpleNamespace(close=Mock(side_effect=interruption))
        with self.assertRaises(KeyboardInterrupt) as caught:
            try:
                raise primary
            finally:
                runner.close_trace_preserving_primary(trace)
        self.assertIs(caught.exception, interruption)
        self.assertIs(interruption.overhead_primary, primary)


if __name__ == "__main__":
    unittest.main()
