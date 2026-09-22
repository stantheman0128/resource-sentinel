"""Portable producer-boundary tests. These do not measure native capability."""
from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.capability_evidence import BuildIdentity, LiveCapabilityContext
from tests.windows import adaptive_capability_runner as runner


class CapabilityProducerBoundaries(unittest.TestCase):
    def test_error_evidence_preserves_api_codes_without_exception_text(self):
        underlying = OSError("private path and command text")
        underlying.win32_error = 5
        underlying.reason = "native_job_query_failed"
        error = runner.NativeRunBlocked("native_cleanup_unverified")
        error.__cause__ = underlying
        observed = runner.error_evidence(error, stage="cleanup")
        self.assertEqual(observed[1]["win32_error"], 5)
        self.assertEqual(observed[1]["reason"], "native_job_query_failed")
        self.assertNotIn("private", json.dumps(observed))

    def test_error_evidence_bounds_cycles_and_refuses_untrusted_reason(self):
        error = OSError("private")
        error.reason, error.win32_error = "C:\\private\\file", True
        error.__cause__ = error
        self.assertEqual(runner.error_evidence(error, stage="query"), [
            dict(stage="query", type="OSError", reason="native_error", win32_error=None)])

    def test_infrastructure_membership_borrows_original_admission_process(self):
        identity = SimpleNamespace(to_dict=lambda: {"pid": 10})
        original = SimpleNamespace(identity=identity, is_in_job=Mock(return_value=False), close=Mock())
        owner = SimpleNamespace(caller=identity, admission=SimpleNamespace(_process=original))
        self.assertEqual(runner.infrastructure_membership(owner, SimpleNamespace(handle=99)),
                         (False, {"pid": 10}))
        original.is_in_job.assert_called_once_with(99)
        original.close.assert_not_called()

    def test_unknown_infrastructure_membership_never_becomes_false(self):
        identity = object()
        original = SimpleNamespace(identity=identity, is_in_job=Mock(return_value=None))
        owner = SimpleNamespace(caller=identity, admission=SimpleNamespace(_process=original))
        with self.assertRaisesRegex(runner.NativeRunBlocked, "native_infrastructure_membership_unknown"):
            runner.infrastructure_membership(owner, SimpleNamespace(handle=99))

    def test_estimate_covers_fixed_workers_and_does_not_follow_pressure(self):
        for n in (1, 2, 8, 12, 32, 64):
            workers, demand = runner.s1_resources(n)
            target, tolerance = .25 * n, max(.15, .025 * n)
            self.assertGreaterEqual(workers * .9, target + tolerance + .25)
            self.assertEqual(demand.cpu_units, min(n, workers + 1))
            self.assertEqual(demand.physical_bytes, 1 << 30)
            self.assertEqual(demand.commit_bytes, 1 << 30)
            self.assertEqual(demand.io_slots, 0)

    def test_bad_denominators_never_round_into_capacity(self):
        for value in (True, 0, 65, 8.0, None):
            with self.subTest(value=value), self.assertRaises(runner.NativeRunBlocked):
                runner.s1_resources(value)

    def test_raw_counter_is_not_reconstructed_from_float_seconds(self):
        counter = (1 << 56) + 3
        first = SimpleNamespace(cpu_100ns=counter, active_processes=4)
        second = SimpleNamespace(cpu_100ns=counter + 600_000_000, active_processes=4)
        job = SimpleNamespace(_native=SimpleNamespace(accounting=Mock(side_effect=(first, second))))
        owner = SimpleNamespace(observation_deadline=120, wait_capped=Mock())
        with patch.object(runner.time, "monotonic_ns", side_effect=(1_000_000_000, 31_000_000_000)):
            result = runner._raw_window(job, owner, capped=True)
        self.assertEqual(result["cpu_start_100ns"], counter)
        self.assertEqual(result["cpu_end_100ns"], counter + 600_000_000)
        self.assertEqual(result["end_ns"] - result["start_ns"], runner.WINDOW_NS)
        owner.wait_capped.assert_called_once_with(30)

    def test_partial_window_is_refused_before_wait(self):
        job = SimpleNamespace(_native=SimpleNamespace(accounting=Mock(return_value=
            SimpleNamespace(cpu_100ns=1, active_processes=1))))
        owner = SimpleNamespace(observation_deadline=20, wait_capped=Mock())
        with patch.object(runner.time, "monotonic_ns", return_value=1), self.assertRaisesRegex(
                runner.NativeRunBlocked, "native_fixed_window_deadline"):
            runner._raw_window(job, owner, capped=True)
        owner.wait_capped.assert_not_called()

    def owner(self, events):
        owner = SimpleNamespace(observation_deadline=1000, execution_id="execution", creation_nonce="nonce",
                                _closed=False)
        owner.restore = Mock(side_effect=lambda: events.append("restore"))
        owner.job = SimpleNamespace(
            query_cpu=Mock(side_effect=lambda: events.append("query") or {"flags": 0}),
            wait_empty=Mock(side_effect=lambda _: events.append("empty") or True),
            _native=SimpleNamespace(accounting=Mock(return_value=SimpleNamespace(active_processes=0))),
            active_pids=Mock(return_value=[]))
        owner.finalize = Mock(side_effect=lambda: events.append("finalize") or {"state": "FINISHED"})
        owner.journal = SimpleNamespace(read=Mock(return_value=SimpleNamespace(pending_intent=None)))
        owner._retain = Mock()
        def close():
            events.append("close")
            owner._closed = True
        owner.close = Mock(side_effect=close)
        return owner

    def test_cleanup_order_preserves_native_proof_before_archive_and_close(self):
        events = []
        owner = self.owner(events)
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "_live_allocations", return_value=0):
            result = runner.cleanup_case(owner, owner.job, Path(temp))
            self.assertTrue((Path(temp) / "stop").exists())
        self.assertEqual(events, ["restore", "query", "empty", "finalize", "close"])
        self.assertEqual(result, dict(cpu_flags=0, active_processes=0, pending_intents=0,
                                     live_allocations=0, unsettled_handles=0))

    def test_failed_restore_still_requests_voluntary_stop_but_never_releases(self):
        owner = self.owner([])
        owner.restore.side_effect = OSError("private detail")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(runner.NativeRunBlocked, "native_cleanup_unverified"):
                runner.cleanup_case(owner, owner.job, Path(temp))
            self.assertTrue((Path(temp) / "stop").exists())
        owner.finalize.assert_not_called()
        owner.close.assert_not_called()
        owner._retain.assert_called_once()

    def test_live_allocation_prevents_close_after_positive_empty(self):
        owner = self.owner([])
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "_live_allocations", return_value=1):
            with self.assertRaises(runner.NativeRunBlocked):
                runner.cleanup_case(owner, owner.job, Path(temp))
        owner.close.assert_not_called()
        owner._retain.assert_called_once()

    def test_cleanup_failure_is_written_without_private_exception_text(self):
        owner = self.owner([])
        with tempfile.TemporaryDirectory() as temp, patch.object(runner, "cleanup_case", side_effect=OSError("secret")):
            record = {"case": "failure"}
            with self.assertRaises(OSError):
                runner.S1Producer._finish(owner, owner.job, Path(temp), record)
            value = (Path(temp) / "native-result.json").read_text("utf-8")
            self.assertNotIn("secret", value)
            self.assertEqual(json.loads(value)["cleanup_failure"]["reason"], "native_cleanup_unverified")

    def test_write_never_overwrites_existing_measurement(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            runner._write_new(path, {"first": 1})
            with self.assertRaises(FileExistsError):
                runner._write_new(path, {"second": 2})
            self.assertEqual(json.loads(path.read_text()), {"first": 1})

    def test_oversized_artifact_is_refused_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            with self.assertRaises(runner.NativeRunBlocked):
                runner._write_new(path, {"data": "x" * runner.MAX_FILE_BYTES})
            self.assertFalse(path.exists())

    def test_p4_larger_artifact_requires_explicit_expected_gate(self):
        value = {"gate": "P4", "data": "x" * runner.MAX_FILE_BYTES}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "P4.json"
            for expected_gate in (None, "S1"):
                with self.subTest(expected_gate=expected_gate):
                    with self.assertRaisesRegex(runner.NativeRunBlocked, "native_artifact_oversized"):
                        runner._write_new(path, value, expected_gate=expected_gate)
                    self.assertFalse(path.exists())
            runner._write_new(path, value, expected_gate="P4")
            self.assertEqual(json.loads(path.read_text("utf-8")), value)

    def test_p4_fixed_limit_refuses_oversize_before_open(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "P4.json"
            with self.assertRaisesRegex(runner.NativeRunBlocked, "native_artifact_oversized"):
                runner._write_new(path, {"data": "x" * runner.MAX_P4_FILE_BYTES}, expected_gate="P4")
            self.assertFalse(path.exists())

    def evidence_run(self, directory):
        # Explicit in-process bookkeeping fixture, never constructor/native gate.
        instance = runner.NativeEvidenceRun.__new__(runner.NativeEvidenceRun)
        instance.directory = Path(directory)
        instance.context = LiveCapabilityContext("c" * 64, 10, 0, 26100, 8, 1, "255",
            "S-1-5-5-100-200", 1, 0, "3.13.0", 64, "d" * 64, False, "e" * 64)
        instance.build = BuildIdentity("a" * 64, "b" * 64)
        instance.revision = "c" * 64
        instance.record = dict(schema_version=1, run_id="76ee5c45-9b6d-4e50-a7bd-1aee287dc01e",
            context=asdict(instance.context), build=asdict(instance.build), profile_revision=instance.revision)
        instance.context_source = lambda: instance.context
        instance.build_source = lambda: instance.build
        return instance

    def test_partial_bundle_has_exact_run_hashes_and_never_promotes(self):
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            result = instance.publish_gate("S1", {"synthetic_unit_data": True})
            self.assertFalse(result["promotion"])
            self.assertEqual(result["measured_gates"], ["S1"])
            bundle = json.loads((Path(temp) / "bundle.json").read_text())
            artifact = json.loads((Path(temp) / "S1.json").read_text())
            self.assertEqual(bundle["run_id"], artifact["run_id"])
            self.assertEqual(bundle["artifacts"][0]["sha256"], result["artifact_sha256"])

    def test_p4_publish_and_reread_use_fixed_expected_gate_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            value = {"synthetic_raw_data": "x" * runner.MAX_FILE_BYTES}
            result = instance.publish_gate("P4", value)
            self.assertEqual(result["measured_gates"], ["P4"])
            self.assertFalse(result["promotion"])
            self.assertGreater((Path(temp) / "P4.json").stat().st_size, runner.MAX_FILE_BYTES)
            result = instance.publish_gate("S1", {})
            self.assertEqual(result["measured_gates"], ["S1", "P4"])

    def test_p4_contents_do_not_enlarge_another_gate_during_bundle_read(self):
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            # Construct untrusted bytes directly: caller expects S1 regardless
            # of the enclosed P4 marker or its oversized native-looking body.
            value = dict(schema_version=1, run_id=instance.record["run_id"],
                gate="P4", evidence_source="native", data="x" * runner.MAX_FILE_BYTES)
            (Path(temp) / "S1.json").write_bytes(runner.canonical(value))
            with self.assertRaisesRegex(runner.evidence.CapabilityEvidenceError, "capability_evidence_oversized"):
                instance.publish_gate("P4", {})
            self.assertFalse((Path(temp) / "bundle.json").exists())

    def test_p4_wrong_gate_or_truncated_envelope_never_publishes_bundle(self):
        for truncated in (False, True):
            with self.subTest(truncated=truncated), tempfile.TemporaryDirectory() as temp:
                instance = self.evidence_run(temp)
                value = dict(schema_version=1, run_id=instance.record["run_id"],
                    gate="P4" if truncated else "S1", evidence_source="native", data={})
                raw = runner.canonical(value)
                (Path(temp) / "P4.json").write_bytes(raw[:-1] if truncated else raw)
                with self.assertRaises(ValueError if truncated else runner.NativeRunBlocked):
                    instance.publish_gate("S1", {})
                self.assertFalse((Path(temp) / "bundle.json").exists())

    def test_build_change_before_publish_never_creates_artifact(self):
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            instance.build_source = lambda: BuildIdentity("d" * 64, "b" * 64)
            with self.assertRaisesRegex(runner.NativeRunBlocked, "native_run_provenance_changed"):
                instance.publish_gate("S1", {})
            self.assertFalse((Path(temp) / "S1.json").exists())

    def test_same_gate_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            instance.publish_gate("S1", {})
            with self.assertRaises(FileExistsError):
                instance.publish_gate("S1", {"changed": True})

    def test_native_entry_does_not_create_job_when_provider_refuses(self):
        from tests.windows.adaptive_admission import ContinuousAdmissionUnavailable
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            with patch("tests.windows.adaptive_admission.require_continuous_admission",
                       side_effect=ContinuousAdmissionUnavailable("continuous_admission_provider_unavailable")), \
                    patch.object(runner, "produce_s1") as produce:
                with self.assertRaises(ContinuousAdmissionUnavailable):
                    instance.run_gate("S1")
                produce.assert_not_called()
            records = list(Path(temp).glob("S1-blocked-*.json"))
            self.assertEqual(len(records), 1)
            self.assertFalse(json.loads(records[0].read_text())["producer_native_work_started"])
            self.assertFalse((Path(temp) / "S1.json").exists())

    def test_native_failure_keeps_exact_coverage_even_when_log_write_fails(self):
        owner = SimpleNamespace(_closed=False)
        coverage = SimpleNamespace(pending_admissions=[], owners=[owner])
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=coverage), \
                    patch.object(runner, "produce_s1", side_effect=RuntimeError("measurement_failed")), \
                    patch.object(runner, "_write_new", side_effect=OSError("disk_full")):
                with self.assertRaises(runner.NativeRunUnsettled) as caught:
                    instance.run_gate("S1")
            self.assertIs(caught.exception.coverage, coverage)
            self.assertIs(caught.exception.coverage.owners[0], owner)
            self.assertFalse((Path(temp) / "S1.json").exists())

    def test_success_data_with_unclosed_owner_is_not_published(self):
        coverage = SimpleNamespace(pending_admissions=[], owners=[SimpleNamespace(_closed=False)])
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=coverage), \
                    patch.object(runner, "produce_s1", return_value={"cannot_promote": True}):
                with self.assertRaises(runner.NativeRunUnsettled):
                    instance.run_gate("S1")
            self.assertFalse((Path(temp) / "S1.json").exists())

    def test_preflight_failure_keeps_coverage_acquired_before_first_case(self):
        admission = object()
        coverage = SimpleNamespace(pending_admissions=[admission], owners=[])
        with tempfile.TemporaryDirectory() as temp:
            instance = self.evidence_run(temp)
            with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=coverage), \
                    patch.object(instance, "assert_unchanged",
                        side_effect=runner.NativeRunBlocked("native_run_provenance_changed")), \
                    patch.object(runner, "produce_s1") as produce:
                with self.assertRaises(runner.NativeRunUnsettled) as caught:
                    instance.run_gate("S1")
                produce.assert_not_called()
            self.assertIs(caught.exception.coverage, coverage)
            self.assertIs(caught.exception.coverage.pending_admissions[0], admission)
            self.assertFalse((Path(temp) / "S1.json").exists())


if __name__ == "__main__":
    unittest.main()
