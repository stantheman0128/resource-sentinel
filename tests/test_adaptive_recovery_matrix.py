"""Portable S3 matrix ownership/bookkeeping; these are not native results."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive.capability_evidence import S3_CASES
from tests.windows import adaptive_recovery_runner as runner


RUN = "61c69f2d-ded8-49c0-8320-912633c346bf"


class RecoveryMatrixTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.matrix = runner.RecoveryMatrix(self.directory, RUN)

    def test_fixed_matrix_has_exact_fourteen_by_ten_sequential_cases(self):
        expected = {(case, iteration) for case in S3_CASES for iteration in range(1, 11)}
        self.assertEqual(len(self.matrix.schedule), 140)
        self.assertEqual(set(self.matrix.schedule), expected)
        self.assertEqual(len(set(self.matrix.schedule)), 140)
        self.assertEqual(self.matrix.schedule[:10], tuple(("intent_before", n) for n in range(1, 11)))

    def test_pending_case_cannot_be_skipped_restarted_or_published(self):
        original = self.matrix.begin_case(10)
        self.assertEqual((original.case, original.iteration), self.matrix.schedule[0])
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "case_unsettled"):
            self.matrix.begin_case(11)
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "matrix_incomplete"):
            self.matrix.data()
        self.assertIs(self.matrix._pending, original)

    def test_dictionary_or_callback_cannot_assert_native_completion(self):
        spec = self.matrix.begin_case(10)
        for value in ({"spec": spec, "closed": True}, SimpleNamespace(spec=spec, closed=True), lambda: True):
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "original_completed_observer_required"):
                self.matrix.record_completed(value, actor_paths=[], ended_tick=11)
        self.assertEqual(self.matrix._cases, [])

    def test_reused_scope_nonce_is_refused_before_new_case(self):
        self.matrix._nonces.add("a" * 32)
        with patch.object(runner, "uuid4", return_value=SimpleNamespace(hex="a" * 32)):
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "scope_reused"):
                self.matrix.begin_case(10)
        self.assertIsNone(self.matrix._pending)

    def test_unclosed_or_different_original_observer_cannot_advance(self):
        spec = self.matrix.begin_case(10)
        # Explicit synthetic object construction tests the gate; it opens no
        # Job or process and never produces an accepted native observation.
        observer = object.__new__(runner.NativeCaseObserver)
        observer.spec, observer.closed, observer.close_started = spec, False, False
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "original_completed_observer_required"):
            self.matrix.record_completed(observer, actor_paths=[], ended_tick=11)
        observer.closed = observer.close_started = True
        observer.spec = runner.CaseSpec(RUN, spec.case, spec.iteration, spec.scope_nonce, spec.started_tick)
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "original_completed_observer_required"):
            self.matrix.record_completed(observer, actor_paths=[], ended_tick=11)
        self.assertEqual(self.matrix._cases, [])

    def test_actor_collection_bounds_many_individually_valid_tiny_logs(self):
        spec = self.matrix.begin_case(10)
        path = self.directory / "actor.jsonl"
        raw = runner.RawEvents(spec, path)
        raw.append("writer_instrumentation_ready", tick=11, role="guardian", boundary="NativeJob._set")
        consumed = []
        def paths():
            for index in range(1000):
                consumed.append(index)
                yield path
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "actor_log_count_limit"):
            runner.collect_actor_events(paths(), spec)
        self.assertEqual(len(consumed), runner.MAX_ACTOR_LOGS + 1)

    def test_actor_collection_bounds_aggregate_bytes_before_reading_another_file(self):
        spec = self.matrix.begin_case(10)
        path = self.directory / "actor.jsonl"
        raw = runner.RawEvents(spec, path)
        raw.append("writer_instrumentation_ready", tick=11, role="guardian", boundary="NativeJob._set")
        size = path.stat().st_size
        with patch.object(runner, "MAX_TOTAL_RAW_BYTES", size), \
                patch.object(runner, "read_actor_events", wraps=runner.read_actor_events) as read:
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "actor_total_log_limit"):
                runner.collect_actor_events((path, path), spec)
            read.assert_called_once()

    def test_replacement_actor_readiness_does_not_redate_original_writer_instrumentation(self):
        spec = self.matrix.begin_case(10)
        paths = []
        for name, role, tick in (("supervisor", "supervisor", 11), ("original", "guardian", 12),
                                 ("replacement", "guardian", 20)):
            path = self.directory / (name + ".jsonl")
            runner.RawEvents(spec, path).append("writer_instrumentation_ready", tick=tick,
                                               role=role, boundary="NativeJob._set")
            paths.append(path)
        records = runner.collect_actor_events(paths, spec)
        ready = [row for row in records if row["event"] == "instrumentation_ready"]
        self.assertEqual(ready[0]["tick"], 12)
        self.assertEqual(len([row for row in records if row["event"] == "writer_instrumentation_ready"]), 3)


if __name__ == "__main__":
    unittest.main()
