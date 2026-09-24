"""Isolated filesystem/thread contracts; these are not native P4 gate evidence."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID

from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.telemetry import (
    AGGREGATE_SECONDS, MAX_BYTES, MAX_AGE_NS, MAX_PENDING, MAX_RECORD_BYTES,
    ResidentTelemetry, SharedTelemetryStore, TelemetryBusy, TelemetryError,
    TelemetryKind, _FileOwner, _StoragePolicy, emit_resident,
    start_resident_telemetry, stop_resident_telemetry,
)

NOW = 1_800_000_000_000_000_000
IDENTITY = ProcessIdentity(7001, 134343072000000001, "S-1-5-5-1-2")
INSTANCE = str(UUID(int=1))


def line(size=100):
    return (json.dumps({"event": "fixture", "padding": "x" * (size - 35)},
                       separators=(",", ":")) + "\n").encode("utf-8")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.now = NOW
        self.policy = _StoragePolicy(max_bytes=401, chunk_bytes=150, max_files=8)
        self.store = self.make_store()
        self.store.start()

    def make_store(self, **kwargs):
        return SharedTelemetryStore(self.directory, policy=self.policy,
                                    utc_ns=lambda: self.now, **kwargs)

    def append(self, kind=TelemetryKind.AGGREGATE, seq=1):
        result = self.store.append(kind, ((seq, line()),))
        self.now += 1
        return result

    def test_actual_complete_records_and_byte_conservation(self):
        result = self.append()
        self.assertEqual(result.before_bytes, 1)
        self.assertEqual(result.after_bytes, 1 + len(line()))
        self.assertEqual(result.after_bytes,
                         result.before_bytes + result.written_bytes - result.deleted_bytes)
        self.assertEqual(json.loads((self.store.directory / result.inventory[0].name).read_text())["event"],
                         "fixture")
        self.assertEqual(self.store.retained_files, 0)

    def test_shared_quota_is_not_repeated_for_each_owner(self):
        second = self.make_store()
        second.start()
        sizes = []
        for seq in range(1, 12):
            store = self.store if seq % 2 else second
            result = store.append(TelemetryKind.EVENT, ((seq, line()),))
            sizes.append(result.after_bytes)
            self.now += 1
        self.assertTrue(all(size <= self.policy.max_bytes for size in sizes))
        self.assertGreater(result.deleted_bytes, 0)
        self.assertEqual(result.after_bytes,
                         1 + sum(item.size for item in second.inventory()))

    def test_oldest_aggregate_is_evicted_before_older_event(self):
        event = self.append(TelemetryKind.EVENT).inventory[0]
        oldest_aggregate = next(item for item in self.append().inventory if item.kind == "aggregate")
        self.append()
        self.append()
        result = self.append()
        self.assertIn(oldest_aggregate.name, {item.name for item in result.deleted})
        self.assertIn(event.name, {item.name for item in result.inventory})

    def test_seven_day_expiry_deletes_only_telemetry_chunks(self):
        journal = self.directory / "recovery"
        journal.mkdir()
        protected = journal / (str(UUID(int=50)) + ".json")
        protected.write_bytes(b"active recovery evidence")
        self.append(TelemetryKind.EVENT)
        self.now += MAX_AGE_NS + 1
        result = self.append()
        self.assertEqual(len(result.deleted), 1)
        self.assertEqual(protected.read_bytes(), b"active recovery evidence")

    def test_unknown_file_is_never_deleted_or_treated_as_zero(self):
        foreign = self.store.directory / "recovery-manifest.json"
        foreign.write_bytes(b"keep")
        with self.assertRaisesRegex(TelemetryError, "telemetry_inventory_unknown"):
            self.append()
        self.assertEqual(foreign.read_bytes(), b"keep")

    def test_recovery_directory_overlap_refuses_before_creation(self):
        with tempfile.TemporaryDirectory() as root:
            data = Path(root)
            store = SharedTelemetryStore(data, excluded_paths=(data / "adaptive-telemetry" / "recovery",))
            with self.assertRaisesRegex(TelemetryError, "telemetry_recovery_directory_overlap"):
                store.start()
            self.assertFalse(store.directory.exists())

    def test_path_redirect_is_refused_without_removing_target(self):
        # Explicit stat seam avoids requiring Developer Mode/symlink privilege.
        import sentinel.adaptive.telemetry as module
        original = module.os.lstat
        def redirected(path):
            result = original(path)
            if Path(path) == self.store.directory:
                return SimpleNamespace(st_mode=result.st_mode, st_nlink=1,
                    st_file_attributes=0x400, st_dev=result.st_dev, st_ino=result.st_ino)
            return result
        with patch.object(module.os, "lstat", side_effect=redirected):
            with self.assertRaisesRegex(TelemetryError, "telemetry_path_unsafe"):
                self.append()
        self.assertTrue(self.store.directory.is_dir())

    def test_short_write_retains_partial_record_and_refuses_later_append(self):
        import sentinel.adaptive.telemetry as module
        self.append()  # initialize the separate lock file
        write = os.write
        def partial(fd, payload):
            return write(fd, payload[:10])
        with patch.object(module.os, "write", side_effect=partial):
            with self.assertRaisesRegex(TelemetryError, "telemetry_write_incomplete"):
                self.append()
        with self.assertRaisesRegex(TelemetryError, "telemetry_partial_record"):
            self.append()
        self.assertEqual(self.store.retained_files, 0)

    def test_disk_full_never_falls_back_to_unaccounted_write(self):
        import sentinel.adaptive.telemetry as module
        self.append()
        with patch.object(module.os, "write", side_effect=OSError(28, "fixture full")):
            with self.assertRaises(OSError):
                self.append()
        self.assertEqual(self.store.retained_files, 0)
        self.assertLessEqual(sum(path.stat().st_size for path in self.store.directory.iterdir()),
                             self.policy.max_bytes)

    def test_read_only_rotation_failure_preserves_remaining_chunks(self):
        for _ in range(4):
            self.append()
        before = {item.name for item in self.store.inventory()}
        with patch("sentinel.adaptive.telemetry.os.unlink", side_effect=PermissionError("fixture")):
            with self.assertRaises(PermissionError):
                self.append()
        self.assertEqual({item.name for item in self.store.inventory()}, before)

    def test_lock_contention_returns_busy_without_wait_or_append(self):
        lock = self.store._acquire_lock()
        try:
            second = self.make_store()
            second.start()
            with self.assertRaises(TelemetryBusy):
                second.append(TelemetryKind.EVENT, ((1, line()),))
            self.assertEqual(second.retained_files, 0)
            self.assertEqual(list(self.store.directory.glob("*.jsonl")), [])
        finally:
            self.store._unlock_close(lock)

    def test_no_fsync_on_telemetry_path(self):
        with patch("sentinel.adaptive.telemetry.os.fsync", side_effect=AssertionError("fsync forbidden")):
            self.append()

    def test_backward_or_future_chunk_clock_refuses_retention_claim(self):
        self.append()
        self.now -= 100
        with self.assertRaisesRegex(TelemetryError, "telemetry_utc_regressed"):
            self.append()
        fresh = self.make_store()
        fresh.start()
        with self.assertRaisesRegex(TelemetryError, "telemetry_utc_regressed"):
            fresh.append(TelemetryKind.EVENT, ((2, line()),))

    def test_chunk_count_bound_rotates_without_ignoring_metadata_byte(self):
        self.policy = _StoragePolicy(max_bytes=2000, chunk_bytes=150, max_files=3)
        self.store = self.make_store()
        self.store.start()
        for _ in range(8):
            result = self.append()
            self.assertLessEqual(len(list(self.store.directory.iterdir())), 3)
            self.assertEqual(result.after_bytes, 1 + sum(item.size for item in result.inventory))

    def test_policy_fixture_cannot_increase_formal_limits(self):
        for change in ({"max_bytes": MAX_BYTES + 1}, {"max_age_ns": MAX_AGE_NS + 1}):
            with self.assertRaises(ValueError):
                _StoragePolicy(**change)

    def test_ambiguous_close_keeps_owner_and_never_closes_again(self):
        owner = _FileOwner()
        path = self.directory / "owned-fd"
        owner.acquire(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        real_fd = owner.fd
        # Simulate the syscall succeeding and the wrapper then being interrupted.
        real_close = os.close
        calls = []
        def ambiguous(fd):
            calls.append(fd)
            real_close(fd)
            raise KeyboardInterrupt()
        with patch("sentinel.adaptive.telemetry.os.close", side_effect=ambiguous):
            with self.assertRaises(KeyboardInterrupt):
                owner.close()
            with self.assertRaisesRegex(TelemetryError, "telemetry_file_cleanup_unknown"):
                owner.close()
        self.assertEqual(calls, [real_fd])
        self.assertEqual(owner.fd, real_fd)

    def test_interrupted_open_retains_unknown_owner_without_reopen_or_close(self):
        real_open, real_close = os.open, os.close
        allocated = []
        error = KeyboardInterrupt()
        def interrupted(*args, **kwargs):
            allocated.append(real_open(*args, **kwargs))
            raise error
        try:
            with patch("sentinel.adaptive.telemetry.os.open", side_effect=interrupted) as opened:
                with self.assertRaises(KeyboardInterrupt):
                    self.append()
                self.assertEqual(self.store.retained_files, 1)
                owner, = self.store._owners
                self.assertTrue(owner.acquire_uncertain)
                self.assertIs(owner.acquire_error, error)
                self.assertIs(self.store._quarantine_error, error)
                with self.assertRaisesRegex(TelemetryError, "telemetry_file_cleanup_unknown"):
                    self.append()
                with self.assertRaisesRegex(TelemetryError, "telemetry_file_cleanup_unknown"):
                    owner.close()
                self.assertEqual(opened.call_count, 1)
        finally:
            # Only the fault fixture knows which fd the interrupted syscall
            # allocated. Production must retain the unknown original owner.
            for fd in allocated:
                real_close(fd)

    def test_known_open_failure_does_not_retain_a_nonexistent_descriptor(self):
        with patch("sentinel.adaptive.telemetry.os.open", side_effect=PermissionError("fixture")):
            with self.assertRaises(PermissionError):
                self.append()
        self.assertEqual(self.store.retained_files, 0)
        self.assertFalse(self.store._quarantined)

    def test_interrupted_lock_acquire_keeps_exact_lock_and_quarantines_store(self):
        real_lock = self.store._lock
        error = KeyboardInterrupt()
        acquired = []
        def interrupted(fd, acquire):
            real_lock(fd, acquire)
            acquired.append(fd)
            raise error
        try:
            with patch.object(self.store, "_lock", side_effect=interrupted) as locked:
                with self.assertRaises(KeyboardInterrupt):
                    self.append()
                owner, = self.store._owners
                self.assertEqual(owner.fd, acquired[0])
                self.assertIs(self.store._quarantine_error, error)
                with self.assertRaisesRegex(TelemetryError, "telemetry_file_cleanup_unknown"):
                    self.store.inventory()
                self.assertEqual(locked.call_count, 1)
        finally:
            # Explicit external fixture teardown; the quarantined store must
            # neither guess the lock outcome nor repeat native cleanup.
            for fd in acquired:
                real_lock(fd, False)
                os.close(fd)

    def test_replaced_lock_leaf_is_not_used_as_shared_accounting_lock(self):
        self.append()
        lock_path = self.store.directory / "telemetry.lock"
        saved_path = self.directory / "original-lock"
        acquire = _FileOwner.acquire
        def replaced(owner, path, flags):
            if Path(path) == lock_path and not flags & os.O_EXCL:
                lock_path.rename(saved_path)
                lock_path.write_bytes(b"\0")
            return acquire(owner, path, flags)
        with patch.object(_FileOwner, "acquire", new=replaced):
            with self.assertRaisesRegex(TelemetryError, "telemetry_file_changed"):
                self.append()
        self.assertEqual(saved_path.read_bytes(), b"\0")
        self.assertEqual(lock_path.read_bytes(), b"\0")
        self.assertEqual(self.store.retained_files, 0)

    def test_replaced_append_leaf_cannot_receive_new_records(self):
        self.policy = _StoragePolicy(max_bytes=2000, chunk_bytes=512, max_files=8)
        self.store = self.make_store()
        self.store.start()
        first = self.append()
        path = self.store.directory / first.inventory[0].name
        saved_path = self.directory / "original-chunk"
        replacement = b"replacement leaf\n"
        acquire = _FileOwner.acquire
        def replaced(owner, candidate, flags):
            if Path(candidate) == path and flags & os.O_APPEND:
                path.rename(saved_path)
                path.write_bytes(replacement)
            return acquire(owner, candidate, flags)
        with patch.object(_FileOwner, "acquire", new=replaced):
            with self.assertRaisesRegex(TelemetryError, "telemetry_file_changed"):
                self.append()
        self.assertEqual(saved_path.read_bytes(), line())
        self.assertEqual(path.read_bytes(), replacement)
        self.assertEqual(self.store.retained_files, 0)


class ResidentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.sinks = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for sink in self.sinks:
            sink.request_stop()
        for sink in self.sinks:
            if sink._thread is not None and sink._thread.ident is not None:
                sink._thread.join(2)
                self.assertFalse(sink._thread.is_alive(), "fixture worker did not stop")
        self.temp.cleanup()

    def sink(self, **changes):
        arguments = dict(data_dir=self.directory, role="helper", identity=IDENTITY, instance_id=INSTANCE)
        arguments.update(changes)
        sink = ResidentTelemetry(**arguments)
        self.sinks.append(sink)
        return sink

    def stop(self, sink):
        sink.request_stop()
        sink._thread.join(2)
        self.assertFalse(sink._thread.is_alive())
        return sink.snapshot()

    def test_real_worker_persists_original_identity_and_receipts(self):
        sink = self.sink().start()
        receipt = sink.offer({"event": "fixture_started", "count": 3})
        status = self.stop(sink)
        self.assertTrue(receipt.accepted)
        self.assertEqual(status["persisted"], 1)
        self.assertEqual(status["pending_records"], 0)
        self.assertIsNone(status["error"])
        write, = sink.receipts()
        record = json.loads((sink.store.directory / write.inventory[0].name).read_text())
        self.assertEqual(record["identity"], IDENTITY.to_dict())
        self.assertEqual(record["instance_id"], INSTANCE)
        self.assertEqual(record["record"], {"event": "fixture_started", "count": 3})

    def test_coalesced_aggregates_are_visible_not_claimed_persisted(self):
        sink = self.sink()
        for count in range(10):
            sink.offer({"event": "helper_host_metrics", "count": count})
        self.assertEqual(sink.snapshot()["pending_records"], 1)
        sink.start()
        status = self.stop(sink)
        self.assertEqual((status["accepted"], status["coalesced"], status["persisted"]), (10, 9, 1))
        chunk, = list(sink.store.directory.glob("*.jsonl"))
        self.assertEqual(json.loads(chunk.read_text())["record"]["count"], 9)

    def test_due_aggregate_is_served_with_continuously_nonempty_event_queue(self):
        clock = [0]
        sink = self.sink(monotonic=lambda: clock[0])
        sink.offer({"event": "helper_host_metrics", "count": 1})
        clock[0] = AGGREGATE_SECONDS
        kinds = []
        for index in range(8):
            sink.offer({"event": "fixture_continuous_event", "index": index})
            with sink._condition:
                kind, _records = sink._batch()
                kinds.append(kind)
                if kind is TelemetryKind.AGGREGATE:
                    break
        self.assertIn(TelemetryKind.AGGREGATE, kinds)
        self.assertEqual(len(sink._events), 1, "due aggregate must not consume/drop queued events")

    def test_iteration_state_transitions_are_events_while_unchanged_state_coalesces(self):
        sink = self.sink(role="guardian")
        first = {"event": "guardian_host_iteration", "state": "ready", "guardian_epoch": "epoch"}
        sink.offer(first)
        sink.offer(dict(first))
        sink.offer(dict(first))
        sink.offer(dict(first, state="draining"))
        self.assertEqual(len(sink._events), 2)
        self.assertEqual(sink.snapshot()["coalesced"], 1)
        self.assertEqual(sink.snapshot()["pending_records"], 3)

    def test_supervisor_recovery_actions_survive_following_quiet_ticks(self):
        sink = self.sink(role="supervisor")
        quiet = {"event": "supervisor_host_iteration", "guardian_epoch": "epoch",
                 "guardian_status": "alive", "inventory_verified": True,
                 "known_executions": ["execution"], "restored_executions": [],
                 "unresolved_executions": [], "slot_released_executions": [],
                 "finalized_executions": [], "drain_unresolved_executions": [],
                 "inventory_error": None, "replacement": None}
        actions = [dict(quiet, **{key: ["execution"]}) for key in
                   ("restored_executions", "slot_released_executions", "finalized_executions")]
        actions += [dict(quiet, replacement={"started": True, "attached": True,
                                           "guardian_epoch": "replacement"}),
                    dict(quiet, helper={"status": "dead", "started": True, "pid": 7010}),
                    dict(quiet, barrier={"complete": True, "pending": False,
                                        "quarantined": False, "reason": None, "changed": True})]
        sink.offer(quiet)
        for record in actions:
            sink.offer(record)
            sink.offer(dict(quiet))
        sink.start()
        self.assertIsNone(self.stop(sink)["error"])
        events = [json.loads(line)["record"] for path in sink.store.directory.glob("event-*.jsonl")
                  for line in path.read_text().splitlines()]
        for record in actions:
            self.assertIn(record, events)

    def test_supervisor_unknown_attachment_and_helper_transitions_emit_once(self):
        sink = self.sink(role="supervisor")
        states = [
            {"guardian_status": "alive", "inventory_verified": True},
            {"guardian_status": "unknown", "inventory_verified": False,
             "inventory_error": "identity_unverified", "unresolved_executions": ["execution"]},
            {"guardian_status": "unattached", "guardian_observed": "alive", "attached": False},
            {"guardian_status": "unattached", "guardian_observed": "alive", "attached": True},
            {"guardian_status": "alive", "helper": {"status": "alive", "started": False}},
            {"guardian_status": "alive", "helper": {"status": "unknown", "started": False,
                                                       "reason": "helper_identity_unverified"}},
            {"guardian_status": "dead", "replacement": {"started": False,
                "reason": "supervisor_host_draining", "registry_removed": True, "registry_reason": None}},
        ]
        for state in states:
            record = {"event": "supervisor_host_iteration", "guardian_epoch": "epoch", **state}
            sink.offer(record)
            sink.offer(dict(record))
        self.assertEqual(len(sink._events), len(states))
        self.assertEqual(sink.snapshot()["coalesced"], len(states) - 1)

    def test_guardian_launch_control_drain_and_retirement_are_discrete_events(self):
        sink = self.sink(role="guardian")
        quiet = {"event": "guardian_host_iteration", "reconciled": [], "reconcile_errors": [],
                 "restored": [], "barrier_clears": [], "barrier_clear_errors": [],
                 "terminal_retirements": [], "prelaunch_retirements": [],
                 **{key: {"served": False, "reason": "pipe_timeout"} for key in
                    ("launch_rpc", "query_rpc", "control_rpc", "operator_rpc")}}
        actions = [dict(quiet, launch_rpc={"served": True, "result": {
            "request_id": "request", "execution_id": "execution", "operation": operation,
            "receipt_verified": True}}) for operation in
            ("PrepareExecution", "ClaimLaunch", "CancelBeforeStart", "StartFailed", "BindRoot")]
        actions += [dict(quiet, control_rpc={"served": True, "result": {
            "execution_id": "execution", "result": outcome, "reason": "fixture_result"}})
            for outcome in ("APPLIED", "RENEWED", "RESTORED", "REJECTED", "UNVERIFIED")]
        actions += [dict(quiet, operator_rpc={"served": True, "result": {
            "operation": operation, "outcome": "complete", "host_state": "draining"}})
            for operation in ("drain", "restore_only")]
        actions.append(dict(quiet, prelaunch_retirements=[
            {"execution_id": "execution", "state": "CANCELLED_BEFORE_START", "terminal": True}]))
        sink.offer(quiet)
        for record in actions:
            sink.offer(record)
            sink.offer(dict(quiet))
        sink.start()
        self.assertIsNone(self.stop(sink)["error"])
        events = [json.loads(line)["record"] for path in sink.store.directory.glob("event-*.jsonl")
                  for line in path.read_text().splitlines()]
        for record in actions:
            self.assertIn(record, events)

    def test_healthy_frame_sequences_coalesce_but_changed_observation_and_clear_emit(self):
        sink = self.sink(role="guardian")
        def frame(seq, *, observation="UNCAPPED", reason="frame_observed", cleared=False):
            return {"event": "guardian_host_iteration", "control_rpc": {"served": True,
                "result": {"sample_seq": seq, "results": [{"execution_id": "execution",
                    "observation": observation, "barrier_cleared": cleared, "reason": reason}]}}}
        sink.offer(frame(1))
        sink.offer(frame(2))
        sink.offer(frame(3))
        self.assertEqual(len(sink._events), 1)
        self.assertEqual(sink.snapshot()["coalesced"], 1)
        sink.offer(frame(4, observation="UNVERIFIED", reason="native_query_failed"))
        sink.offer(frame(5, observation="UNVERIFIED", reason="native_query_failed"))
        self.assertEqual(len(sink._events), 2)
        sink.offer(frame(6, cleared=True))
        sink.offer(frame(7))
        self.assertEqual(len(sink._events), 3)
        self.assertTrue(json.loads(sink._events[-1][1])["record"]["control_rpc"]["result"]["results"][0]["barrier_cleared"])

    def test_repeated_idle_and_readonly_rpc_polling_stays_coalescible(self):
        sink = self.sink(role="guardian")
        idle = {"event": "guardian_host_iteration", **{key: {
            "served": False, "reason": "pipe_timeout"} for key in
            ("launch_rpc", "query_rpc", "control_rpc", "operator_rpc")}}
        for _ in range(5):
            sink.offer(dict(idle))
        self.assertEqual(len(sink._events), 1)
        for seq in range(5):
            sink.offer(dict(idle, query_rpc={"served": True, "result": {
                "request_id": str(seq), "operation": "QueryExecution",
                "receipt_verified": True, "control_writes": False}},
                operator_rpc={"served": True, "result": {"request_id": str(seq),
                    "operation": "describe", "outcome": "complete", "host_state": "ready"}}))
        self.assertEqual(len(sink._events), 2)

    def test_separate_failed_rpc_requests_survive_intervening_idle_polls(self):
        sink = self.sink(role="guardian")
        errors = []
        for key in ("launch_rpc", "query_rpc", "control_rpc", "operator_rpc"):
            record = {"event": "guardian_host_iteration", key: {
                "served": False, "reason": "launch_receipt_invalid"}}
            idle = {"event": "guardian_host_iteration", key: {
                "served": False, "reason": "pipe_timeout"}}
            for _ in range(2):
                sink.offer(record)
                sink.offer(idle)
            errors.append(record)
        sink.start()
        self.assertIsNone(self.stop(sink)["error"])
        events = [json.loads(line)["record"] for path in sink.store.directory.glob("event-*.jsonl")
                  for line in path.read_text().splitlines()]
        for record in errors:
            self.assertEqual(events.count(record), 2)

    def test_rpc_custody_full_without_new_service_attempt_remains_coalescible(self):
        sink = self.sink(role="guardian")
        record = {"event": "guardian_host_iteration", "launch_rpc": {
            "served": False, "reason": "guardian_host_rpc_custody_full"}}
        for _ in range(3):
            sink.offer(record)
        self.assertEqual(len(sink._events), 1)
        self.assertEqual(sink.snapshot()["coalesced"], 1)

    def test_queue_bound_includes_active_batch_and_never_blocks_producer(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        class BlockedStore(SharedTelemetryStore):
            def append(self, kind, records):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError("fixture wait expired")
                return super().append(kind, records)
        sink = self.sink(store_factory=BlockedStore).start()
        sink.offer({"event": "fixture_first"})
        self.assertTrue(entered.wait(2))
        for count in range(MAX_PENDING + 20):
            sink.offer({"event": "fixture_queued", "count": count})
        status = sink.snapshot()
        self.assertEqual(status["pending_records"], MAX_PENDING)
        self.assertGreater(status["dropped"], 0)
        self.assertEqual(status["persisted"], 0)
        release.set()
        self.stop(sink)

    def test_bad_records_are_rejected_before_unbounded_serialization(self):
        sink = self.sink()
        cyclic = {}
        cyclic["cycle"] = cyclic
        for record in ({"value": "x" * MAX_RECORD_BYTES}, {"value": float("nan")},
                       {"value": 1 << 200}, cyclic, {"value": object()}):
            receipt = sink.offer(record)
            self.assertFalse(receipt.accepted)
            self.assertEqual(receipt.outcome, "telemetry_record_invalid")
        self.assertEqual(sink.snapshot()["pending_records"], 0)

    def test_worker_failure_is_visible_and_does_not_raise_into_emit(self):
        class FailedStore(SharedTelemetryStore):
            def start(self):
                raise PermissionError("isolated fixture")
        sink = self.sink(store_factory=FailedStore).start()
        sink._thread.join(2)
        host = SimpleNamespace(telemetry=sink)
        receipt = emit_resident(host, {"event": "guardian_restore_observed"})
        self.assertFalse(receipt.accepted)
        self.assertEqual(sink.snapshot()["error"], "PermissionError")

    def test_events_do_not_delay_due_aggregate_forever(self):
        clock = [0.0]
        sink = self.sink(monotonic=lambda: clock[0])
        sink.offer({"event": "helper_host_metrics"})
        clock[0] = AGGREGATE_SECONDS + 1
        sink.offer({"event": "lifecycle_event"})
        sink.start()
        deadline = time.monotonic() + 2
        while sink.snapshot()["persisted"] != 2 and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertEqual(sink.snapshot()["persisted"], 2)
        status = self.stop(sink)
        self.assertEqual(status["persisted"], 2)
        self.assertEqual({path.name.split("-", 1)[0] for path in sink.store.directory.glob("*.jsonl")},
                         {"event", "aggregate"})

    def test_three_original_roles_share_directory_and_receipts(self):
        sinks = [self.sink(role=role, instance_id=str(UUID(int=index))).start()
                 for index, role in enumerate(("helper", "guardian", "supervisor"), 1)]
        for sink in sinks:
            sink.offer({"event": "resident_started"})
        # Let busy owners actually retry before orderly shutdown; this is a
        # functional concurrency fixture, not a measured overhead assertion.
        deadline = time.monotonic() + 2
        while any(sink.snapshot()["persisted"] != 1 for sink in sinks) and time.monotonic() < deadline:
            time.sleep(.01)
        for sink in sinks:
            self.assertEqual(self.stop(sink)["persisted"], 1)
        records = [json.loads(row) for path in (self.directory / "adaptive-telemetry").glob("*.jsonl")
                   for row in path.read_text().splitlines()]
        self.assertEqual({record["role"] for record in records}, {"helper", "guardian", "supervisor"})
        self.assertLessEqual(sum(path.stat().st_size for path in (self.directory / "adaptive-telemetry").iterdir()), MAX_BYTES)

    def test_busy_shutdown_keeps_unpersisted_batch_explicit(self):
        class BusyStore(SharedTelemetryStore):
            def append(self, kind, records):
                raise TelemetryBusy("fixture_busy")
        sink = self.sink(store_factory=BusyStore).start()
        sink.offer({"event": "pending"})
        status = self.stop(sink)
        self.assertEqual(status["persisted"], 0)
        self.assertEqual(status["pending_records"], 1)

    def test_explicit_stream_stays_separate_from_original_host_sink(self):
        sink = self.sink()
        host = SimpleNamespace(telemetry=sink)
        stream = io.StringIO()
        self.assertTrue(emit_resident(host, {"event": "one_shot"}, stream=stream))
        self.assertEqual(json.loads(stream.getvalue()), {"event": "one_shot"})
        self.assertEqual(sink.snapshot()["offered"], 0)

    def test_original_sink_is_retained_before_start_failure(self):
        error = RuntimeError("fixture")
        class FailedSink:
            def __init__(self, **kwargs):
                self.kwargs = kwargs
            def start(self):
                raise error
        host = SimpleNamespace(telemetry=None, _telemetry_factory=FailedSink)
        result = start_resident_telemetry(host, role="helper", identity=IDENTITY,
            instance_id=INSTANCE, data_dir=self.directory)
        self.assertIs(host.telemetry, result)
        self.assertIs(host._telemetry_start_error, error)
        self.assertEqual(result.kwargs["identity"], IDENTITY)

    def test_stopping_a_host_does_not_rebind_another_hosts_sink(self):
        first, second = self.sink().start(), self.sink(role="guardian", instance_id=str(UUID(int=2))).start()
        host_a, host_b = SimpleNamespace(telemetry=first), SimpleNamespace(telemetry=second)
        emit_resident(host_a, {"event": "helper_started"})
        emit_resident(host_b, {"event": "guardian_started"})
        stop_resident_telemetry(host_a, {"event": "helper_closed"})
        self.assertFalse(second.snapshot()["stopping"])
        self.assertIs(host_b.telemetry, second)
        self.stop(second)


if __name__ == "__main__":
    unittest.main()
