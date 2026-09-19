"""Pure mocks only: no Win32 operation, processes, Jobs or control writes."""
import copy
import ctypes as c
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("job_diagnostics", Path(__file__).with_name("adaptive_job_diagnostics.py"))
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


def identity(pid, birth, **updates):
    result = dict(pid=pid, creation_filetime=str(birth), session_id=2, token_session_id=2,
                  in_any_job=True, elevated=False, integrity_rid=8192, image_path="private-path",
                  user_sid="private-user", logon_sid="private-logon", authentication_luid="private-luid")
    result.update(updates)
    return result


class FakeApi:
    def __init__(self):
        self.rows = {100: identity(100, 1000), 90: identity(90, 900), 80: identity(80, 800)}
        self.opened, self.closed, self.reads = [], [], []
        self.open_failure = self.read_failure = self.close_failure = None
        self.change = None

    def read_process(self, handle, pid):
        assert handle == pid
        self.reads.append(pid)
        if pid == self.read_failure:
            error = RuntimeError("private read error")
            error.win32_error = 5
            raise error
        result = copy.deepcopy(self.rows[pid])
        if self.change and pid == self.change[0] and self.reads.count(pid) >= self.change[1]:
            result["creation_filetime"] = "9999"
        return result

    def open_process(self, pid):
        self.opened.append(pid)
        if pid == self.open_failure:
            raise RuntimeError("private open error")
        return pid

    def close(self, handle):
        self.closed.append(handle)
        if handle == self.close_failure:
            raise RuntimeError("private close error")


class FakeNative:
    def __init__(self):
        self.parents = {100: 90, 90: 80, 80: 0}
        self.job_calls, self.parent_calls = [], []
        self.job_failure = self.parent_failure = None
        self.change_relation = False
        self.values = {"cpu": dict(control_flags=5, cpu_rate_or_weight_raw=2500, min_rate_raw=2500, max_rate_raw=0),
                       "extended_limits": {key: 0 for key in (*diagnostics.LIMIT_FIELDS, *diagnostics.MEMORY_FIELDS)},
                       "ui_restrictions": {"restriction_flags": 0}, "groups": [0],
                       "group_affinity": [{"group": 0, "affinity_mask": 4095}]}

    def job_query(self, name):
        self.job_calls.append(name)
        if name == self.job_failure:
            raise diagnostics.DiagnosticError(f"job_{name}_query", 5, "win32")
        return copy.deepcopy(self.values[name])

    def parent_pid(self, handle, expected_pid):
        assert handle == expected_pid
        self.parent_calls.append(expected_pid)
        if expected_pid == self.parent_failure:
            raise diagnostics.DiagnosticError("parent_relation_query", 0xC0000022, "ntstatus")
        if self.change_relation and expected_pid == 100 and self.parent_calls.count(100) == 2:
            return 81
        return self.parents[expected_pid]


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.api, self.native = FakeApi(), FakeNative()
        self.now = 1.0

    def collect(self, **options):
        with mock.patch.object(diagnostics.os, "getpid", return_value=100):
            return diagnostics.collect_diagnostics(self.api, 100, self.api.rows[100], clock=lambda: self.now,
                                                   deadline=options.get("deadline", 10.0), native=self.native)

    def test_explicit_windows_abi_sizes_independent_of_platform_long(self):
        self.assertEqual(c.sizeof(diagnostics.U32), 4)
        self.assertEqual(c.sizeof(diagnostics.I32), 4)
        for structure, size in ((diagnostics.CpuInformation, 8), (diagnostics.BasicLimits, 64),
                                (diagnostics.ExtendedLimits, 144), (diagnostics.GroupAffinity, 16),
                                (diagnostics.ProcessBasicInformation, 48)):
            self.assertEqual(c.sizeof(structure), size)
        self.assertEqual(diagnostics.ProcessBasicInformation.UniqueProcessId.offset, 32)

    def test_success_remains_diagnostic_and_holds_exact_parent_handles(self):
        report = self.collect()
        self.assertTrue(report["self_rechecked"])
        self.assertEqual(report["lineage"]["validity"], "verified_prefix")
        self.assertEqual(report["lineage"]["stop_reason"], "parent_absent")
        self.assertEqual([row["process"]["pid"] for row in report["lineage"]["parents"]], [90, 80])
        self.assertEqual(self.api.opened, [90, 80])
        self.assertEqual(self.api.closed, [80, 90])
        self.assertNotIn(100, self.api.closed)
        self.assertEqual(report["ancestor_job_hierarchy"], "unknown")
        self.assertEqual(report["effective_inherited_limits"], "unknown")
        self.assertEqual(report["control_eligibility"], "not_assessed")
        self.assertEqual(report["process_control_writes"], 0)
        self.assertFalse(report["immediate_job"]["snapshot_atomic"])
        for secret in ("private-path", "private-user", "private-logon", "private-luid", "image_path"):
            self.assertNotIn(secret, json.dumps(report))

    def test_job_query_failure_is_unknown_not_zero_and_other_reads_continue(self):
        self.native.job_failure = "cpu"
        report = self.collect()
        result = report["immediate_job"]["queries"]["cpu"]
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["value"])
        self.assertEqual(result["error"], {"stage": "job_cpu_query", "code_domain": "win32", "code": 5})
        self.assertEqual(report["immediate_job"]["queries"]["groups"]["status"], "valid")

    def test_no_job_skips_null_job_queries_but_not_parent_lineage(self):
        self.api.rows[100]["in_any_job"] = False
        report = self.collect()
        self.assertEqual(self.native.job_calls, [])
        self.assertEqual(report["immediate_job"]["membership"], "absent")
        self.assertTrue(all(row["status"] == "not_applicable" for row in report["immediate_job"]["queries"].values()))

    def test_expired_deadline_performs_no_native_or_process_read(self):
        report = self.collect(deadline=1.0)
        self.assertEqual(self.api.reads, [])
        self.assertEqual(self.native.job_calls, [])
        self.assertEqual(self.native.parent_calls, [])
        self.assertFalse(report["self_rechecked"])
        self.assertEqual(report["errors"][0]["stage"], "deadline_elapsed")

    def test_slow_job_query_prevents_further_native_calls_and_drops_late_value(self):
        original = self.native.job_query
        def slow(name):
            value = original(name)
            self.now = 11.0
            return value
        with mock.patch.object(self.native, "job_query", side_effect=slow):
            report = self.collect()
        self.assertEqual(self.native.job_calls, ["cpu"])
        self.assertEqual(self.native.parent_calls, [])
        self.assertIsNone(report["immediate_job"]["queries"]["cpu"]["value"])

    def test_final_self_change_or_deadline_preserves_queries_and_downgrades_lineage(self):
        for fault in ("identity", "deadline"):
            with self.subTest(fault=fault):
                self.api, self.native, self.now = FakeApi(), FakeNative(), 1.0
                if fault == "identity":
                    self.api.change = (100, 4)
                    report = self.collect()
                else:
                    read = self.api.read_process
                    def late_read(handle, pid):
                        value = read(handle, pid)
                        if pid == 100 and self.api.reads.count(100) == 4:
                            self.now = 11.0
                        return value
                    with mock.patch.object(self.api, "read_process", side_effect=late_read):
                        report = self.collect()
                self.assertFalse(report["self_rechecked"])
                self.assertTrue(report["errors"])
                self.assertEqual(report["lineage"]["validity"], "unknown")
                self.assertEqual(report["lineage"]["stop_reason"], "unknown")
                self.assertEqual(len(report["lineage"]["parents"]), 2)
                self.assertEqual(report["immediate_job"]["queries"]["cpu"]["status"], "valid")
                self.assertEqual(self.api.closed, [80, 90])

    def test_parent_birth_after_child_or_identity_change_rejected(self):
        for birth in ("1000", "1001"):
            with self.subTest(birth=birth):
                self.api, self.native = FakeApi(), FakeNative()
                self.api.rows[90]["creation_filetime"] = birth
                report = self.collect()
                self.assertEqual(report["lineage"]["parents"], [])
                self.assertEqual(report["lineage"]["errors"][0]["stage"], "parent_birth_not_before_child")
                self.assertEqual(self.api.closed, [90])

    def test_parent_reuse_during_two_reads_and_relation_change_rejected(self):
        self.api.change = (90, 2)
        report = self.collect()
        self.assertEqual(report["lineage"]["parents"], [])
        self.assertEqual(report["lineage"]["errors"][0]["stage"], "parent_identity_changed")
        self.api, self.native = FakeApi(), FakeNative()
        self.native.change_relation = True
        report = self.collect()
        self.assertEqual(report["lineage"]["errors"][0]["stage"], "parent_relation_changed")

    def test_cross_user_logon_luid_or_session_stops_after_boundary_parent(self):
        for field in ("user_sid", "logon_sid", "authentication_luid", "session_id"):
            with self.subTest(field=field):
                self.api, self.native = FakeApi(), FakeNative()
                self.api.rows[90][field] = 3 if field == "session_id" else "other-private"
                report = self.collect()
                self.assertEqual(report["lineage"]["stop_reason"], "security_boundary")
                self.assertEqual(report["lineage"]["validity"], "unknown")
                self.assertEqual(self.api.opened, [90])
                self.assertNotIn(90, self.native.parent_calls)

    def test_maximum_six_hops_and_cycles_stop_without_more_opens(self):
        for pid in range(99, 92, -1):
            self.api.rows[pid] = identity(pid, pid * 10)
            self.native.parents[pid + 1] = pid
        report = self.collect()
        self.assertEqual(report["lineage"]["stop_reason"], "hop_limit")
        self.assertEqual(self.api.opened, [99, 98, 97, 96, 95, 94])
        self.api, self.native = FakeApi(), FakeNative()
        self.native.parents[90] = 100
        report = self.collect()
        self.assertEqual(report["lineage"]["errors"][0]["stage"], "parent_cycle")
        self.assertEqual(self.api.opened, [90])

    def test_query_failure_and_cleanup_failure_are_sanitized_and_close_others(self):
        self.native.parent_failure = 80
        self.api.close_failure = 80
        report = self.collect()
        self.assertEqual(self.api.closed, [80, 90])
        self.assertEqual(report["lineage"]["validity"], "unknown")
        self.assertEqual([item["stage"] for item in report["lineage"]["errors"]], ["parent_relation_query", "parent_close"])
        self.assertNotIn("private", json.dumps(report))

    def test_sanitizer_rejects_unknown_keys_private_strings_and_unbounded_values(self):
        original = self.collect()
        mutations = [lambda row: row.update(secret="private"),
                     lambda row: row["self"].update(image_path="private"),
                     lambda row: row["immediate_job"]["queries"]["cpu"]["value"].update(extra=True),
                     lambda row: row.update(process_control_writes=True),
                     lambda row: row.update(ancestor_job_hierarchy="known"),
                     lambda row: row["lineage"].update(max_hops=7),
                     lambda row: row["lineage"].update(stop_reason=[]),
                     lambda row: row["lineage"].update(stop_reason="hop_limit"),
                     lambda row: row["immediate_job"].update(membership="absent"),
                     lambda row: row["immediate_job"].update(membership="unknown"),
                     lambda row: row["lineage"]["parents"][0]["matches"].update(same_session=False),
                     lambda row: row["lineage"]["parents"][0]["matches"].update(same_user="private"),
                     lambda row: row["self"].update(creation_filetime="private-path"),
                     lambda row: row["immediate_job"]["queries"]["groups"].update(value=list(range(65))),
                     lambda row: row["immediate_job"]["queries"]["ui_restrictions"].update(value={"restriction_flags": float("nan")})]
        for mutate in mutations:
            value = copy.deepcopy(original)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                diagnostics.sanitize_diagnostics(value)

    def test_sanitizer_security_boundary_requires_matching_stop_and_error(self):
        self.api.rows[90]["user_sid"] = "other-user"
        original = self.collect()
        value = copy.deepcopy(original)
        value["lineage"]["stop_reason"] = "parent_absent"
        with self.assertRaises(ValueError):
            diagnostics.sanitize_diagnostics(value)
        value = copy.deepcopy(original)
        value["lineage"]["errors"] = []
        with self.assertRaises(ValueError):
            diagnostics.sanitize_diagnostics(value)

    def test_sanitizer_absent_and_unknown_membership_require_consistent_evidence(self):
        self.api.rows[100]["in_any_job"] = False
        value = self.collect()
        value["immediate_job"]["queries"]["cpu"] = diagnostics._unknown("job_state_unknown")
        with self.assertRaises(ValueError):
            diagnostics.sanitize_diagnostics(value)
        self.api, self.native = FakeApi(), FakeNative()
        value = self.collect(deadline=1.0)
        self.assertEqual(value["immediate_job"]["membership"], "unknown")
        value["errors"] = []
        with self.assertRaises(ValueError):
            diagnostics.sanitize_diagnostics(value)

    def test_boundary_cleanup_failure_preserves_boundary_and_attempts_close(self):
        self.api.rows[90]["logon_sid"] = "other-logon"
        self.api.close_failure = 90
        report = self.collect()
        self.assertEqual(report["lineage"]["stop_reason"], "security_boundary")
        self.assertEqual([row["stage"] for row in report["lineage"]["errors"]],
                         ["parent_security_boundary", "parent_close"])
        self.assertEqual(self.api.closed, [90])

    def test_sanitizer_rejects_unrecognized_error_stages_and_unknown_with_values(self):
        self.native.job_failure = "cpu"
        original = self.collect()
        for stage in ("private-path", "CreateProcess", 1):
            value = copy.deepcopy(original)
            value["immediate_job"]["queries"]["cpu"]["error"]["stage"] = stage
            with self.assertRaises(ValueError):
                diagnostics.sanitize_diagnostics(value)
        value = copy.deepcopy(original)
        value["immediate_job"]["queries"]["cpu"]["value"] = 0
        with self.assertRaises(ValueError):
            diagnostics.sanitize_diagnostics(value)

    def test_sanitizer_returns_detached_copy(self):
        report = self.collect()
        sanitized = diagnostics.sanitize_diagnostics(report)
        sanitized["self"]["pid"] = 2
        self.assertEqual(report["self"]["pid"], 100)

    def test_native_query_uses_null_job_bounded_buffer_and_exact_return_length(self):
        adapter = diagnostics.NativeDiagnostics.__new__(diagnostics.NativeDiagnostics)
        calls = []
        def query(handle, information_class, output, length, written):
            calls.append((handle, information_class, length))
            value = c.cast(output, c.POINTER(diagnostics.CpuInformation)).contents
            value.ControlFlags, value.RateUnion = 5, 2500
            c.cast(written, c.POINTER(diagnostics.U32))[0] = 8
            return 1
        adapter.query = query
        self.assertEqual(adapter.job_query("cpu")["cpu_rate_or_weight_raw"], 2500)
        self.assertEqual(calls, [(None, 15, 8)])
        def short(_handle, _kind, _buffer, _size, written):
            c.cast(written, c.POINTER(diagnostics.U32))[0] = 4
            return 1
        adapter.query = short
        with self.assertRaises(diagnostics.DiagnosticError) as failure:
            adapter.job_query("cpu")
        self.assertEqual(failure.exception.stage, "job_cpu_size")

    def test_native_group_query_never_retries_oversize_or_partial_entry(self):
        adapter = diagnostics.NativeDiagnostics.__new__(diagnostics.NativeDiagnostics)
        for name, reported in (("groups", 129), ("groups", 1), ("group_affinity", 1025), ("group_affinity", 17)):
            calls = []
            def query(_handle, _kind, _buffer, size, written):
                calls.append(size)
                c.cast(written, c.POINTER(diagnostics.U32))[0] = reported
                return 1
            adapter.query = query
            with self.subTest(name=name, reported=reported), self.assertRaises(diagnostics.DiagnosticError):
                adapter.job_query(name)
            self.assertEqual(len(calls), 1)
            self.assertLessEqual(calls[0], 1024)

    def test_native_parent_query_checks_status_size_and_held_pid(self):
        adapter = diagnostics.NativeDiagnostics.__new__(diagnostics.NativeDiagnostics)
        def query(handle, information_class, output, size, written):
            self.assertEqual((handle, information_class, size), (55, 0, 48))
            value = c.cast(output, c.POINTER(diagnostics.ProcessBasicInformation)).contents
            value.UniqueProcessId, value.InheritedFromUniqueProcessId = 100, 90
            c.cast(written, c.POINTER(diagnostics.U32))[0] = 48
            return 0
        adapter.parent_query = query
        self.assertEqual(adapter.parent_pid(55, 100), 90)
        with self.assertRaises(diagnostics.DiagnosticError):
            adapter.parent_pid(55, 101)
        adapter.parent_query = lambda *_args: -1073741790
        with self.assertRaises(diagnostics.DiagnosticError) as failure:
            adapter.parent_pid(55, 100)
        self.assertEqual(failure.exception.domain, "ntstatus")
        self.assertEqual(failure.exception.code, 0xC0000022)


if __name__ == "__main__":
    unittest.main()
