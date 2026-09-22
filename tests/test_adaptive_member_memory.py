"""Portable failure/ownership tests; fixtures are not native capability evidence."""
from __future__ import annotations

import ctypes as C
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.helper_host import HelperHost, JobHandleSource
from sentinel.adaptive.member_memory import (
    MemberMemoryError, NativeMemberMemoryScanner, NativeMemoryReader, NativeScanBudget,
    _CountersEx2, _supported_ex2_os,
)

LOGON = "S-1-5-5-1-2"
START = 100_000_000
SECOND = 10_000_000


def execution(number):
    return str(UUID(int=number))


class Clock:
    def __init__(self):
        self.now = START

    def __call__(self):
        return self.now


class Process:
    def __init__(self, pid, *, birth=134343072000000001):
        self.identity = ProcessIdentity(pid, birth, LOGON)
        self.status = IdentityStatus.ALIVE
        self.jobs = {1}
        self._lock = threading.Lock()
        self._handle = pid + 1000
        self._close_outcome_unknown = False
        self.close_error = None
        self.close_calls = 0

    def observe(self):
        return IdentityObservation(self.identity, self.status)

    def is_in_job(self, handle):
        return handle in self.jobs

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self._handle = None


class Job:
    logon_sid = LOGON

    def __init__(self, pids=(101,), *, handle=1):
        self.pids, self.handle = pids, handle
        self.total = self.active = len(pids)
        self.cpu = 100
        self.accounting_calls = self.list_calls = self.close_calls = 0
        self.list_hook = self.accounting_hook = None

    def accounting(self):
        self.accounting_calls += 1
        if self.accounting_hook:
            self.accounting_hook()
        return SimpleNamespace(total_processes=self.total, active_processes=self.active,
                               cpu_100ns=self.cpu)

    def active_pids(self):
        self.list_calls += 1
        if self.list_hook:
            self.list_hook()
        return self.pids

    def close(self):
        self.close_calls += 1


class Reader:
    def __init__(self):
        self.calls = []
        self.hook = None

    def read(self, process):
        self.calls.append(process.identity)
        if self.hook:
            return self.hook(process)
        return 10, 20


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.clock, self.reader = Clock(), Reader()
        self.processes = {pid: Process(pid) for pid in (101, 102, 103)}
        self.opens = []
        self.scanner = NativeMemberMemoryScanner(clock=self.clock, backend=self.reader,
                                                open_process=self.open_process)
        self.job = Job()

    def open_process(self, pid):
        self.opens.append(pid)
        return self.processes[pid]

    def sample(self, jobs=None, budget=None):
        return self.scanner.scan_frame(jobs or {execution(1): self.job}, self.clock(), budget=budget)

    def test_complete_private_values_and_same_handles_are_reused(self):
        first, = self.sample()
        self.assertEqual((first.reason, first.private_working_set_bytes, first.private_commit_bytes),
                         ("ok", 10, 20))
        self.clock.now += SECOND
        second, = self.sample()
        self.assertEqual(second.reason, "ok")
        self.assertEqual(self.opens, [101])
        self.assertEqual(self.job.list_calls, 1)
        self.clock.now += SECOND
        self.sample()
        self.assertEqual(self.job.list_calls, 2)
        self.assertEqual(self.opens, [101])

    def test_unlisted_new_process_is_unknown_until_bounded_refresh(self):
        self.sample()
        self.job.total, self.job.active, self.job.pids = 2, 2, (101, 102)
        self.clock.now += SECOND
        pending, = self.sample()
        self.assertEqual(pending.reason, "membership_refresh_pending")
        self.assertIsNone(pending.private_commit_bytes)
        self.assertEqual(self.job.list_calls, 1)
        self.clock.now += SECOND
        refreshed, = self.sample()
        self.assertEqual((refreshed.reason, refreshed.private_working_set_bytes), ("ok", 20))
        self.assertEqual(self.opens, [101, 102])

    def test_transient_birth_exit_changes_total_even_when_active_matches(self):
        def during_read(process):
            self.job.total += 1
            return 10, 20
        self.reader.hook = during_read
        result, = self.sample()
        self.assertEqual(result.reason, "membership_changed")
        self.assertIsNone(result.private_working_set_bytes)

    def test_partial_or_duplicate_membership_never_opens_processes(self):
        for pids, active in (((101,), 2), ((101, 101), 2)):
            with self.subTest(pids=pids):
                self.job.pids, self.job.active, self.job.total = pids, active, active
                result, = self.sample()
                self.assertEqual(result.reason, "membership_changed")
                self.assertEqual(self.opens, [])
                self.clock.now += 2 * SECOND

    def test_membership_limit_is_checked_before_first_process_open(self):
        self.job.pids = tuple(range(1, 258))
        self.job.active = self.job.total = 257
        result, = self.sample()
        self.assertEqual(result.reason, "member_limit_exceeded")
        self.assertEqual(self.opens, [])

    def test_global_record_budget_is_shared_across_jobs(self):
        budget = NativeScanBudget(START, max_members=1)
        jobs = {execution(1): self.job, execution(2): Job((102,))}
        one, two = self.sample(jobs, budget)
        self.assertEqual((one.reason, two.reason), ("ok", "member_limit_exceeded"))
        self.assertEqual(budget.consumed_members, 1)
        self.assertTrue(budget.exhausted)
        self.assertEqual(self.opens, [101])

    def test_query_only_shards_share_deadline_and_record_allowance(self):
        other = NativeMemberMemoryScanner(clock=self.clock, backend=self.reader,
                                          open_process=self.open_process)
        budget = NativeScanBudget(START, max_members=1)
        self.sample(budget=budget)
        result, = other.scan_frame({execution(2): Job((102,))}, START, budget=budget)
        self.assertEqual(result.reason, "member_limit_exceeded")
        self.assertEqual(self.opens, [101])

    def test_expensive_pid_list_consumes_deadline_before_open(self):
        self.job.list_hook = lambda: setattr(self.clock, "now", START + 1_000_001)
        result, = self.sample()
        self.assertEqual(result.reason, "member_scan_timeout")
        self.assertEqual(self.opens, [])

    def test_timeout_after_first_member_drops_partial_sum_and_later_job(self):
        self.job.pids, self.job.total, self.job.active = (101, 102), 2, 2
        def expensive(process):
            self.clock.now += 1_000_001
            return 10, 20
        self.reader.hook = expensive
        one, two = self.sample({execution(1): self.job, execution(2): Job((103,))})
        self.assertEqual((one.reason, two.reason), ("member_scan_timeout", "member_scan_timeout"))
        self.assertIsNone(one.private_commit_bytes)
        self.assertEqual(self.opens, [101])

    def test_early_member_exit_during_later_member_read_is_unknown(self):
        self.job.pids, self.job.total, self.job.active = (101, 102), 2, 2
        def exit_early(process):
            if process.identity.pid == 102:
                self.processes[101].status = IdentityStatus.DEAD
            return 10, 20
        self.reader.hook = exit_early
        result, = self.sample()
        self.assertEqual(result.reason, "member_identity_changed")
        self.assertIsNone(result.private_working_set_bytes)

    def test_dead_cached_birth_is_not_reopened_in_the_same_frame(self):
        self.sample()
        old = self.processes[101]
        old.status = IdentityStatus.DEAD
        self.processes[101] = Process(101, birth=old.identity.created_filetime_100ns + 1)
        self.clock.now += SECOND
        result, = self.sample()
        self.assertEqual(result.reason, "member_identity_changed")
        self.assertEqual(self.opens, [101])
        self.assertEqual(old.close_calls, 1)
        self.job.total += 1  # genuine replacement birth increments Job lifetime total
        self.clock.now += SECOND
        new, = self.sample()
        self.assertEqual(new.reason, "ok")
        self.assertEqual(self.opens, [101, 101])

    def test_wrong_logon_or_pid_never_reaches_memory_query(self):
        self.processes[101].identity = ProcessIdentity(102, 134343072000000001, LOGON)
        result, = self.sample()
        self.assertEqual(result.reason, "member_identity_changed")
        self.assertEqual(self.reader.calls, [])

    def test_inaccessible_member_never_returns_partial_sum(self):
        self.job.pids, self.job.total, self.job.active = (101, 999), 2, 2
        result, = self.sample()
        self.assertEqual(result.reason, "inaccessible_identity")
        self.assertIsNone(result.private_commit_bytes)
        self.assertEqual(result.attempted_members, 2)

    def test_same_exact_member_invalidates_both_jobs(self):
        self.processes[101].jobs.add(2)
        one, two = self.sample({execution(1): self.job, execution(2): Job(handle=2)})
        self.assertEqual((one.reason, two.reason), ("member_overlap", "member_overlap"))
        self.assertIsNone(one.private_commit_bytes)

    def test_cross_shard_overlap_invalidates_earlier_receipt(self):
        other = NativeMemberMemoryScanner(clock=self.clock, backend=self.reader,
                                          open_process=self.open_process)
        budget = NativeScanBudget(START)
        one, = self.sample(budget=budget)
        two, = other.scan_frame({execution(2): Job()}, START, budget=budget)
        self.assertEqual(one.reason, "ok")  # immutable earlier receipt
        self.assertEqual(two.reason, "member_overlap")
        self.assertEqual(budget.invalid_execution_ids, {execution(1), execution(2)})

    def test_nonmember_and_unsupported_memory_stay_unknown(self):
        self.processes[101].jobs.clear()
        result, = self.sample()
        self.assertEqual(result.reason, "membership_changed")
        self.processes[101].jobs.add(1)
        def unavailable(process):
            raise MemberMemoryError("ex2_unavailable")
        self.reader.hook = unavailable
        result, = self.sample()
        self.assertEqual(result.reason, "ex2_unavailable")
        self.assertIsNone(result.private_working_set_bytes)

    def test_empty_verified_job_is_legitimately_zero(self):
        self.job.pids, self.job.active, self.job.total = (), 0, 2
        result, = self.sample()
        self.assertEqual((result.reason, result.private_working_set_bytes,
                          result.private_commit_bytes), ("ok", 0, 0))

    def test_release_closes_cached_process_once_and_never_closes_borrowed_job(self):
        self.sample()
        self.assertIsNone(self.scanner.release(execution(1)))
        self.scanner.close()
        self.assertEqual(self.processes[101].close_calls, 1)
        self.assertEqual(self.job.close_calls, 0)

    def test_unknown_close_is_retained_not_retried_and_blocks_same_pid(self):
        self.sample()
        process = self.processes[101]
        process.close_error = RuntimeError("uncertain close")
        process._close_outcome_unknown = True
        self.assertEqual(self.scanner.release(execution(1)), "member_cleanup_unverified")
        self.scanner.retry_cleanup()
        self.assertEqual(process.close_calls, 1)
        result, = self.sample()
        self.assertEqual(result.reason, "member_cleanup_unverified")
        self.assertEqual(self.opens, [101])
        with self.assertRaises(MemberMemoryError):
            self.scanner.close()
        self.assertEqual(process.close_calls, 1)

    def test_known_failed_close_has_bounded_explicit_retry(self):
        self.sample()
        process = self.processes[101]
        process.close_error = RuntimeError("explicit backend FALSE fixture")
        self.scanner.release(execution(1))
        self.assertEqual(self.scanner.retained_uncertain, 1)
        process.close_error = None
        self.scanner.retry_cleanup()
        self.assertEqual((self.scanner.retained_uncertain, process.close_calls), (0, 2))

    def test_interrupted_open_retains_attached_owner_and_never_reopens(self):
        error = KeyboardInterrupt()
        owner = self.processes[101]
        owner._close_outcome_unknown = True
        error._identity_handle_cleanup = (owner,)
        def interrupted(pid):
            raise error
        self.scanner._opener = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.sample()
        self.assertTrue(self.scanner.retained_uncertain)
        self.assertIs(self.scanner._retained[0][1], error)
        self.scanner.retry_cleanup()
        self.assertEqual(owner.close_calls, 0)

    def test_successful_other_close_does_not_unblock_quarantined_same_pid(self):
        # Different retained handles to one native identity can exist before
        # overlap detection invalidates both aggregates.
        first, second = Process(101), Process(101)
        first.jobs.add(2)
        second.jobs.add(2)
        owners = iter((first, second))
        self.scanner._opener = lambda pid: next(owners)
        self.sample({execution(1): self.job, execution(2): Job(handle=2)})
        first._close_outcome_unknown = True
        first.close_error = RuntimeError("unknown")
        self.scanner.release(execution(1))
        self.scanner.release(execution(2))
        self.assertIn(101, self.scanner._blocked_pids)
        result, = self.sample()
        self.assertEqual(result.reason, "member_cleanup_unverified")

    def test_one_scanner_refuses_more_than_ten_jobs(self):
        with self.assertRaises(ValueError):
            self.sample({execution(i): Job() for i in range(1, 12)})

    def test_invalid_or_extended_budget_is_refused(self):
        for args in ((START, 257, 100), (START, 256, 101), (True, 256, 100)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                NativeScanBudget(*args)


class NativeMemoryContractTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.ws = 7

    def query(self, handle, ptr, length):
        self.calls.append(handle)
        data = C.cast(ptr, C.POINTER(_CountersEx2)).contents
        C.memset(ptr, 0, length)
        data.cb = length
        data.WorkingSetSize = 100
        data.PrivateWorkingSetSize = self.ws
        data.PrivateUsage = 30
        return 1

    def reader(self, query=None, supported=True):
        return NativeMemoryReader(query=self.query if query is None else query,
                                  supported_os=supported, current_handle=999)

    def test_x64_documented_layout(self):
        if C.sizeof(C.c_void_p) == 8:
            self.assertEqual(C.sizeof(_CountersEx2), 96)
            self.assertEqual(_CountersEx2.PrivateUsage.offset, 72)
            self.assertEqual(_CountersEx2.PrivateWorkingSetSize.offset, 80)
            self.assertEqual(_CountersEx2.SharedCommitUsage.offset, 88)

    def test_os_scope_requires_cu_revision(self):
        for build, revision, expected in ((19045, 3447, False), (19045, 3448, True),
                                         (22621, 2282, False), (22621, 2283, True),
                                         (22631, 0, True), (22000, 9000, False)):
            self.assertEqual(_supported_ex2_os(build, revision), expected)
        self.assertFalse(_supported_ex2_os(19045, None))

    def test_probe_is_once_and_zero_member_private_ws_is_valid(self):
        reader = self.reader()
        self.assertEqual(reader.read(Process(101)), (7, 30))
        self.ws = 0
        self.assertEqual(reader.read(Process(102)), (0, 30))
        self.assertEqual(self.calls, [999, 1101, 1102])

    def test_old_os_does_not_query_or_fallback_to_rss(self):
        with self.assertRaisesRegex(MemberMemoryError, "ex2_unavailable"):
            self.reader(supported=False).read(Process(101))
        self.assertEqual(self.calls, [])

    def test_success_with_untouched_extension_is_not_support(self):
        def old_api(handle, ptr, length):
            data = C.cast(ptr, C.POINTER(_CountersEx2)).contents
            data.cb = length
            data.WorkingSetSize = 100
            data.PrivateUsage = 30
            return 1
        with self.assertRaisesRegex(MemberMemoryError, "ex2_unavailable"):
            self.reader(old_api).read(Process(101))

    def test_output_cb_must_actually_be_written(self):
        def no_cb(handle, ptr, length):
            self.query(handle, ptr, length)
            C.cast(ptr, C.POINTER(_CountersEx2)).contents.cb = 0
            return 1
        with self.assertRaisesRegex(MemberMemoryError, "ex2_unavailable"):
            self.reader(no_cb).read(Process(101))

    def test_own_zero_probe_or_private_exceeding_ws_refuses(self):
        for value in (0, 101):
            with self.subTest(value=value):
                self.ws = value
                with self.assertRaisesRegex(MemberMemoryError, "ex2_unavailable"):
                    self.reader().read(Process(101))

    def test_closed_or_quarantined_process_never_reaches_member_api(self):
        reader = self.reader()
        reader.read(Process(101))
        for attribute, value in (("_handle", None), ("_close_outcome_unknown", True)):
            process = Process(102)
            setattr(process, attribute, value)
            with self.assertRaisesRegex(MemberMemoryError, "inaccessible_identity"):
                reader.read(process)
        self.assertEqual(self.calls, [999, 1101])


class JobSourceMemoryTests(unittest.TestCase):
    # Reuse explicit synthetic fixtures without inheriting/duplicating tests.
    open_process = ScannerTests.open_process

    def setUp(self):
        ScannerTests.setUp(self)
        self.source = JobHandleSource()
        self.source.add(execution(1), self.job, membership_provable=True)
        self.source.configure_memory(self.scanner)

    def test_scan_result_is_current_and_can_be_consumed_only_once(self):
        self.source.begin_sample(START, (execution(1),))
        before = self.job.accounting_calls
        reading = self.source.read(execution(1))
        self.assertEqual(self.job.accounting_calls - before, 1)
        self.assertEqual((reading.private_working_set_bytes, reading.private_commit_bytes), (10, 20))
        self.assertEqual(self.source.memory_sample_started_tick, START)
        self.assertEqual(self.source.last_memory_scan[0].reason, "ok")
        self.assertIsNone(self.source.read(execution(1)).private_commit_bytes)

    def test_accounting_change_after_scan_suppresses_memory_only(self):
        self.source.begin_sample(START, (execution(1),))
        self.job.total += 1
        reading = self.source.read(execution(1))
        self.assertIsNone(reading.private_working_set_bytes)
        self.assertTrue(reading.membership_complete)
        self.assertEqual(reading.cpu_100ns, 100)

    def test_memory_failure_drops_prior_frame_and_keeps_cpu_read(self):
        self.source.begin_sample(START, (execution(1),))
        with patch.object(self.scanner, "scan_frame", side_effect=OSError("fixture")):
            self.source.begin_sample(START + SECOND, (execution(1),))
        reading = self.source.read(execution(1))
        self.assertEqual(reading.cpu_100ns, 100)
        self.assertIsNone(reading.private_working_set_bytes)
        self.assertEqual(self.source.last_memory_scan, ())

    def test_missing_external_budget_cannot_reset_allowance(self):
        self.source.configure_memory(self.scanner, budget_source=lambda: None)
        self.source.begin_sample(START, (execution(1),))
        self.assertEqual(self.opens, [])
        reading = self.source.read(execution(1))
        self.assertEqual(reading.cpu_100ns, 100)
        self.assertIsNone(reading.private_commit_bytes)

    def test_incomplete_job_containment_is_not_memory_scanned(self):
        self.source.add(execution(2), Job((102,)), membership_provable=False)
        self.source.begin_sample(START, (execution(1), execution(2)))
        self.assertEqual(self.opens, [101])
        self.assertFalse(self.source.read(execution(2)).membership_complete)

    def test_scanner_with_owned_member_handles_cannot_be_replaced(self):
        self.source.begin_sample(START, (execution(1),))
        with self.assertRaisesRegex(ValueError, "helper_memory_scanner_owned"):
            self.source.configure_memory(None)
        budget = NativeScanBudget(START)
        supplier = lambda: budget
        self.source.configure_memory(self.scanner, budget_source=supplier)
        self.assertIs(self.source.memory_scanner, self.scanner)
        self.assertIs(self.source.memory_budget_source, supplier)

    def test_release_retains_memory_cleanup_and_still_closes_job(self):
        self.source.begin_sample(START, (execution(1),))
        process = self.processes[101]
        process._close_outcome_unknown = True
        process.close_error = RuntimeError("uncertain")
        self.assertEqual(self.source.release(execution(1)), "member_cleanup_unverified")
        self.assertEqual(self.source.retained_uncertain, 1)
        self.assertEqual(self.job.close_calls, 1)
        self.source.retry_memory_cleanup()
        self.assertEqual(process.close_calls, 1)

    def test_interrupted_scanner_release_retains_custody_and_closes_job(self):
        failure = KeyboardInterrupt()
        with patch.object(self.scanner, "release", side_effect=failure):
            self.assertEqual(self.source.release(execution(1)), "member_cleanup_unverified")
        self.assertEqual(self.source.retained_uncertain, 1)
        self.assertEqual(self.job.close_calls, 1)
        self.assertIs(self.source._retained[0].member_cleanup_error, failure)
        self.assertIsNone(self.source.release(execution(1)))
        self.assertEqual(self.job.close_calls, 1)

    def test_host_close_retries_first_known_member_close_failure_before_success(self):
        self.source.begin_sample(START, (execution(1),))
        process = self.processes[101]
        def fails_once():
            process.close_calls += 1
            if process.close_calls == 1:
                raise RuntimeError("known FALSE fixture")
            process._handle = None
        process.close = fails_once
        host = HelperHost(data_dir="unused-fixture", clock=self.clock,
                          machine_source=lambda: None)
        host.jobs = self.source
        host.shadow = SimpleNamespace(release=lambda key: None)
        result = host.close()
        self.assertEqual(result["handles_retained_uncertain"], 0)
        self.assertEqual(process.close_calls, 2)

    def test_drain_enrollment_retries_known_member_close_failure(self):
        from tests.test_adaptive_helper import profile
        self.source.begin_sample(START, (execution(1),))
        process = self.processes[101]
        process.close_error = RuntimeError("known FALSE fixture")
        self.source.release(execution(1))
        process.close_error = None
        host = HelperHost(data_dir="unused-fixture", clock=self.clock,
                          machine_source=lambda: None)
        host.jobs, host.profile, host._started = self.source, profile(), True
        host._ledger_candidates = lambda: ([], False, 0)
        record = host.refresh_enrollment()
        self.assertEqual(record["cleanup_unverified"], [])
        self.assertEqual(self.source.retained_uncertain, 0)
        self.assertEqual(process.close_calls, 2)

    def test_job_sampler_runs_memory_batch_and_preserves_cpu_on_failure(self):
        from sentinel.adaptive.sampler import JobSampler
        from tests.test_adaptive_helper import profile
        sampler = JobSampler(backend=self.source, profile=profile(), clock=self.clock)
        sampler.enroll(execution(1))
        first = sampler.sample()
        self.assertEqual(first.jobs[0].private_working_set_bytes, 10)
        self.clock.now += SECOND
        self.job.cpu += SECOND
        with patch.object(self.scanner, "scan_frame", side_effect=OSError("fixture")):
            second = sampler.sample()
        self.assertEqual(second.jobs[0].cpu_units, 1.0)
        self.assertTrue(second.jobs[0].membership_complete)
        self.assertIsNone(second.jobs[0].private_commit_bytes)
        self.assertEqual([error.code for error in second.errors], ["memory_attribution_unavailable"])

    def test_host_native_wiring_is_lazy_and_explicit_source_fixtures_stay_portable(self):
        host = HelperHost(data_dir="unused-fixture")
        self.assertIsNone(host.jobs.memory_scanner)
        host._clock = self.clock
        host._configure_memory()
        self.assertIsInstance(host.jobs.memory_scanner, NativeMemberMemoryScanner)
        self.assertIsNone(host.jobs.memory_scanner._backend)  # no native DLL load
        fixture = HelperHost(data_dir="unused-fixture", clock=self.clock,
                             machine_source=lambda: None)
        fixture._configure_memory()
        self.assertIsNone(fixture.jobs.memory_scanner)
        explicit = HelperHost(data_dir="unused-fixture", clock=self.clock,
                              machine_source=lambda: None, memory_scanner=self.scanner)
        explicit._configure_memory()
        self.assertIs(explicit.jobs.memory_scanner, self.scanner)


if __name__ == "__main__":
    unittest.main()
