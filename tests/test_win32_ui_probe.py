"""Portable bookkeeping tests; none runs or claims a native responsiveness gate."""
import contextlib
import io
import json
import math
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from tests.fixtures import win32_ui_probe as probe


class ProbeConfigTests(unittest.TestCase):
    def test_finite_bounded_defaults(self):
        self.assertEqual(probe.ProbeConfig().duration_seconds, 60.0)
        self.assertEqual(probe.ProbeConfig(3600, 20, 100000).max_samples, 100000)

    def test_duration_rejects_nonfinite_bool_and_unbounded(self):
        for value in (True, "1", 0, .9, 3601, math.inf, -math.inf, math.nan):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.ProbeConfig(duration_seconds=value)

    def test_interval_rejects_busy_loop(self):
        for value in (False, 0, 1, 19, 1001, 100.0, "100"):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.ProbeConfig(interval_ms=value)

    def test_sample_storage_is_bounded(self):
        for value in (True, 0, 100001, 2.0):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                probe.ProbeConfig(max_samples=value)


class RecorderTests(unittest.TestCase):
    def setUp(self):
        self.recorder = probe.ProbeRecorder(2)

    def complete(self, offset=0):
        sequence = self.recorder.enqueue(100 + offset)
        self.assertTrue(self.recorder.dispatch(sequence, 120 + offset))
        self.recorder.request_paint(130 + offset)
        self.assertTrue(self.recorder.paint(150 + offset, 160 + offset))
        return sequence

    def test_preserves_each_native_timestamp(self):
        self.complete()
        self.assertEqual(self.recorder.samples, [{
            "sequence": 1, "enqueued_ns": 100, "dispatch_ns": 120,
            "paint_requested_ns": 130, "paint_ns": 150, "paint_finished_ns": 160,
        }])
        self.assertIsNone(self.recorder.pending)

    def test_one_outstanding_prevents_coalesced_paint_attribution(self):
        self.assertEqual(self.recorder.enqueue(100), 1)
        self.assertIsNone(self.recorder.enqueue(101))
        self.assertEqual(self.recorder.pending["enqueued_ns"], 100)

    def test_wrong_and_duplicate_dispatch_are_ignored(self):
        self.recorder.enqueue(100)
        self.assertFalse(self.recorder.dispatch(2, 110))
        self.assertTrue(self.recorder.dispatch(1, 120))
        self.assertFalse(self.recorder.dispatch(1, 130))
        self.assertEqual(self.recorder.pending["dispatch_ns"], 120)

    def test_unrelated_native_paint_does_not_create_a_sample(self):
        self.assertFalse(self.recorder.paint(100, 110))
        self.recorder.enqueue(120)
        self.assertFalse(self.recorder.paint(130, 140))
        self.assertEqual(self.recorder.samples, [])

    def test_paint_requires_dispatch(self):
        with self.assertRaisesRegex(probe.ProbeError, "paint_without_dispatch"):
            self.recorder.request_paint(100)
        self.recorder.enqueue(100)
        with self.assertRaisesRegex(probe.ProbeError, "paint_without_dispatch"):
            self.recorder.request_paint(110)

    def test_duplicate_redraw_does_not_shorten_measured_latency(self):
        self.recorder.enqueue(100)
        self.recorder.dispatch(1, 110)
        self.recorder.request_paint(120)
        with self.assertRaisesRegex(probe.ProbeError, "duplicate_paint_request"):
            self.recorder.request_paint(130)
        self.assertEqual(self.recorder.pending["paint_requested_ns"], 120)

    def test_regressing_dispatch_clock_rejected(self):
        self.recorder.enqueue(100)
        with self.assertRaisesRegex(probe.ProbeError, "clock_regressed"):
            self.recorder.dispatch(1, 99)

    def test_regressing_paint_request_clock_rejected(self):
        self.recorder.enqueue(100)
        self.recorder.dispatch(1, 110)
        with self.assertRaisesRegex(probe.ProbeError, "clock_regressed"):
            self.recorder.request_paint(109)

    def test_regressing_paint_or_completion_clock_rejected(self):
        self.recorder.enqueue(100)
        self.recorder.dispatch(1, 110)
        self.recorder.request_paint(120)
        for started, finished in ((119, 130), (130, 129)):
            with self.subTest(started=started, finished=finished):
                with self.assertRaisesRegex(probe.ProbeError, "clock_regressed"):
                    self.recorder.paint(started, finished)
        self.assertEqual(self.recorder.samples, [])

    def test_invalid_timestamp_type_is_not_coerced(self):
        for value in (True, 1.5, -1):
            with self.subTest(value=value), self.assertRaises(probe.ProbeError):
                self.recorder.enqueue(value)

    def test_limit_stops_storage_and_sequence_reuse(self):
        self.assertEqual(self.complete(), 1)
        self.assertEqual(self.complete(100), 2)
        self.assertIsNone(self.recorder.enqueue(500))
        self.assertEqual(len(self.recorder.samples), 2)


class StatisticsTests(unittest.TestCase):
    def test_no_samples_produces_null_not_zero(self):
        self.assertEqual(probe.distribution([]), {"count": 0, "p50": None, "p95": None, "p99": None})

    def test_known_interpolation(self):
        values = [30, 0, 20, 10]
        self.assertEqual(probe.percentile(values, .5), 15)
        self.assertAlmostEqual(probe.percentile(values, .95), 28.5)
        self.assertEqual(values, [30, 0, 20, 10])

    def test_one_native_sample_is_reported_without_inventing_more(self):
        self.assertEqual(probe.distribution([12]), {"count": 1, "p50": 12, "p95": 12, "p99": 12})


class ProducerShutdownTests(unittest.TestCase):
    def test_stop_between_outer_check_and_lock_does_not_enqueue(self):
        stop = threading.Event()
        recorder = probe.ProbeRecorder(1)
        post = Mock(return_value=True)

        class StopAtLockEntry:
            def __enter__(self):
                stop.set()

            def __exit__(self, *_):
                return False

        probe._produce_samples(probe.ProbeConfig(), recorder, StopAtLockEntry(),
                               stop, post, clock=lambda: 100)
        post.assert_not_called()
        self.assertIsNone(recorder.pending)

    def test_failed_native_post_is_an_error_with_retained_incomplete_sample(self):
        recorder = probe.ProbeRecorder(1)
        with self.assertRaisesRegex(probe.ProbeError, "post_message_failed"):
            probe._produce_samples(probe.ProbeConfig(), recorder, threading.Lock(),
                                   threading.Event(), lambda _: False, clock=lambda: 100)
        self.assertEqual(recorder.pending, {"sequence": 1, "enqueued_ns": 100})


class FixtureOutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()

    def test_publish_preserves_existing_evidence(self):
        path = self.directory / "output.json"
        probe.publish_json(path, {"one": 1})
        with self.assertRaisesRegex(probe.ProbeError, "path_already_exists"):
            probe.publish_json(path, {"two": 2})
        self.assertEqual(json.loads(path.read_text()), {"one": 1})

    def test_missing_parent_is_not_automatically_created(self):
        with self.assertRaises(OSError):
            probe.validate_path(self.directory / "missing" / "output.json")

    def test_relative_path_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, "path_must_be_absolute_local"):
            probe.validate_path("output.json")

    def test_parent_traversal_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, "path_must_be_absolute_local"):
            probe.validate_path(self.directory / ".." / "output.json")

    def test_production_namespace_rejected(self):
        with self.assertRaisesRegex(probe.ProbeError, "production_directory_forbidden"):
            probe.validate_path(self.directory / ".resource-sentinel" / "output.json")

    def test_directory_cannot_be_stop_file(self):
        with self.assertRaisesRegex(probe.ProbeError, "path_not_regular"):
            probe.validate_path(self.directory)

    def test_existing_stop_file_refuses_new_run(self):
        stop = self.directory / "stop"
        stop.write_text("")
        with patch.object(probe, "run_probe") as run, contextlib.redirect_stderr(io.StringIO()):
            result = probe.main(["--output", str(self.directory / "result.json"), "--stop-file", str(stop)])
        self.assertEqual(result, 2)
        run.assert_not_called()

    def test_equal_output_and_stop_paths_refused(self):
        path = str(self.directory / "result.json")
        with patch.object(probe, "run_probe") as run, contextlib.redirect_stderr(io.StringIO()):
            result = probe.main(["--output", path, "--stop-file", path])
        self.assertEqual(result, 2)
        run.assert_not_called()

    def test_cli_publishes_structured_block_without_claiming_measurement(self):
        output = self.directory / "result.json"
        blocked = probe._result(probe.ProbeConfig())
        blocked["reason"] = "process_is_in_job"
        with patch.object(probe, "run_probe", return_value=blocked):
            self.assertEqual(probe.main(["--output", str(output)]), 2)
        data = json.loads(output.read_text())
        self.assertEqual(data["status"], "blocked")
        self.assertEqual(data["samples"], [])
        self.assertIsNone(data["dispatch_ms"]["p95"])

    def test_invalid_duration_never_starts_native_work(self):
        with patch.object(probe, "run_probe") as run, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(probe.main(["--output", str(self.directory / "result.json"),
                                         "--duration-seconds", "nan"]), 2)
        run.assert_not_called()


class UnsupportedHostTests(unittest.TestCase):
    def test_foreign_job_never_qualifies(self):
        with self.assertRaisesRegex(probe.ProbeError, "process_is_in_job"):
            probe.require_native_context(True, probe.NORMAL_PRIORITY_CLASS)

    def test_all_non_normal_priority_classes_are_refused(self):
        for value in (0, 0x40, 0x80, 0x100, 0x4000, 0x8000):
            with self.subTest(value=value):
                with self.assertRaisesRegex(probe.ProbeError, "process_priority_not_normal"):
                    probe.require_native_context(False, value)

    def test_unknown_context_cannot_be_coerced_to_safe(self):
        for membership, priority in ((0, 32), (None, 32), (False, "32")):
            with self.subTest(membership=membership, priority=priority):
                with self.assertRaisesRegex(probe.ProbeError, "native_context_unverified"):
                    probe.require_native_context(membership, priority)

    def test_normal_unmanaged_context_is_eligible(self):
        self.assertIsNone(probe.require_native_context(False, probe.NORMAL_PRIORITY_CLASS))

    def test_non_windows_never_calls_native_or_labels_measured(self):
        with patch.object(probe.os, "name", "posix"), patch.object(probe, "_run_windows") as native:
            result = probe.run_probe(probe.ProbeConfig())
        native.assert_not_called()
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "windows_required")
        self.assertEqual(result["samples"], [])
        self.assertIsNone(result["outside_job"])
        self.assertIsNone(result["priority_class"])
        self.assertTrue(result["cleanup_complete"])


if __name__ == "__main__":
    unittest.main()
