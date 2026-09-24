"""Portable observation/conservation tests, never native P4 evidence."""
from copy import deepcopy
from dataclasses import replace
import gc
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
import weakref
from unittest.mock import patch

from sentinel.adaptive import capability_evidence as ce
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive import telemetry as log
from tests.test_adaptive_capability_evidence import LOGON, p4_data, telemetry_data
from tests.test_adaptive_decision import SHADOW
from tests.windows.adaptive_overhead_telemetry import (
    CohortTelemetryTrace, NativeTelemetryObservation, NativeTelemetryProbe, TelemetryEvidenceError,
)
from tests.windows import adaptive_overhead_telemetry as observed


class ClosedTelemetryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.value = telemetry_data()
        self.context = SimpleNamespace(logon_id=LOGON)

    def verify(self, value=None, **kwargs):
        return ce._p4_telemetry(self.value if value is None else value, self.context, **kwargs)

    def reject(self, reason, value=None, **kwargs):
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, reason):
            self.verify(value, **kwargs)

    def test_exact_sequences_file_inventories_and_metadata_conserve_bytes(self):
        self.assertEqual(self.verify(reports=[(20, 512)]), 10497)

    def test_native_unsigned_volume_and_128_bit_file_id_are_not_measurement_counters(self):
        wide = [(1 << 64) - 1, (1 << 128) - 1]
        self.value["lock_identity"] = wide
        for sink in self.value["sinks"]:
            for write in sink["writes"]:
                write["lock_identity"] = wide
        # The actual chunk identity must also preserve its full native width.
        for entries in [self.value["final_inventory"], *[
                write[key] for sink in self.value["sinks"] for write in sink["writes"]
                for key in ("before", "after", "deleted")]]:
            for entry in entries:
                entry[4] = [(1 << 64) - 1, (1 << 100) + entry[4][1]]
        self.assertEqual(self.verify(), 10497)

    def test_file_identity_overflow_boolean_and_unknown_zero_are_refused(self):
        for identity in ([1 << 64, 1], [1, 1 << 128], [True, 1], [1, False], [0, 1], [1, 0]):
            with self.subTest(identity=identity):
                value = deepcopy(self.value)
                value["lock_identity"] = identity
                self.reject("measurement_invalid", value)

    def test_queued_required_report_is_not_persisted(self):
        sink = self.value["sinks"][0]
        sink["offers"].append([21, 512, "aggregate", None])
        sink["status"].update(offered=21, accepted=21, pending_records=1)
        self.reject("report_not_persisted", reports=[(21, 512)])

    def test_coalesced_required_report_is_not_persisted(self):
        sink = self.value["sinks"][0]
        sink["offers"].extend([[21, 512, "aggregate", None], [22, 512, "aggregate", 21]])
        sink["status"].update(offered=22, accepted=22, coalesced=1, pending_records=1)
        self.reject("report_not_persisted", reports=[(21, 512)])

    def test_discrete_event_cannot_be_coalesced(self):
        sink = self.value["sinks"][1]
        sink["offers"].append([2, 512, "aggregate", 1])
        self.reject("coalescing_invalid")

    def test_persisted_sequence_cannot_also_be_coalesced(self):
        self.value["sinks"][0]["offers"].append([21, 512, "aggregate", 20])
        self.reject("persistence_invalid")

    def test_boolean_sequence_refused(self):
        self.value["sinks"][0]["offers"][0][0] = True
        self.reject("measurement_invalid")

    def test_missing_sequence_refused(self):
        self.value["sinks"][0]["offers"].pop(0)
        self.reject("offer_coverage_invalid")

    def test_duplicate_persisted_sequence_refused(self):
        self.value["sinks"][0]["writes"][1]["offers"][0][0] = 1
        self.reject("persistence_invalid")

    def test_missing_append_receipt_cannot_be_inferred_from_final_size(self):
        self.value["sinks"][0]["writes"].pop(0)
        self.reject("write_coverage_invalid")

    def test_same_size_file_replacement_refused(self):
        self.value["sinks"][0]["writes"][1]["after"][0][4] = [1, 99]
        self.reject("file_conservation_failed")

    def test_unreported_deletion_refused(self):
        self.value["sinks"][1]["writes"][0]["after"].pop(0)
        self.reject("file_conservation_failed")

    def test_fake_deletion_receipt_refused(self):
        self.value["sinks"][0]["writes"][0]["deleted"] = deepcopy(self.value["final_inventory"])
        self.reject("file_conservation_failed")

    def test_append_bytes_are_not_size_counter_guess(self):
        self.value["sinks"][0]["writes"][0]["after"][0][1] += 1
        self.reject("file_conservation_failed")

    def test_independent_final_inventory_is_required(self):
        self.value["final_inventory"][0][1] += 1
        self.reject("final_inventory_mismatch")

    def test_lock_replacement_refused(self):
        self.value["sinks"][1]["writes"][0]["lock_identity"] = [1, 99]
        self.reject("write_coverage_invalid")

    def test_writer_clock_regression_refused(self):
        self.value["sinks"][0]["writes"][1]["utc_ns"] -= 2
        self.reject("clock_invalid")

    def test_age_expiration_cannot_be_claimed_with_expired_chunk_left(self):
        self.value["sinks"][0]["writes"][-1]["utc_ns"] += log.MAX_AGE_NS + 1
        self.reject("file_conservation_failed")

    def test_unknown_extra_schema_field_refused(self):
        self.value["bounded"] = True
        self.reject("schema_invalid")

    def test_policy_increase_refused(self):
        self.value["max_bytes"] += 1
        self.reject("binding_invalid")

    def test_missing_resident_role_refused(self):
        self.value["sinks"].pop()
        self.reject("measurement_missing")

    def test_dropped_report_or_degraded_sink_cannot_pass(self):
        for key, value in (("dropped", 1), ("error", "disk_full"), ("pending_records", 129)):
            with self.subTest(key=key):
                data = deepcopy(self.value)
                data["sinks"][0]["status"][key] = value
                self.reject("degraded", data)

    def test_counter_mismatch_refused(self):
        self.value["sinks"][0]["status"]["written_bytes"] += 1
        self.reject("counter_mismatch")

    def test_original_helper_instance_and_sequence_binding_required(self):
        self.reject("binding_invalid", helper_instance="00000000-0000-4000-8000-000000000003")
        self.reject("report_not_persisted", reports=[(1, 513)])

    def test_prefill_cannot_hide_missing_earlier_writer(self):
        # Every role-local receipt remains internally consistent, but the
        # shared chain has no genuine empty starting inventory.
        alien = [f"event-{1799999999999999999:020d}-{'f' * 32}.jsonl", 16,
                 1799999999999999999, "event", [1, 99]]
        for sink in self.value["sinks"]:
            for write in sink["writes"]:
                write["before"].append(deepcopy(alien))
                write["after"].append(deepcopy(alien))
            sink["status"]["inventory_bytes"] += 16
        self.value["final_inventory"].append(alien)
        self.reject("shared_write_coverage_incomplete")

    def test_old_synchronous_p4_schema_is_not_reinterpreted(self):
        data = p4_data(SHADOW)
        del data["schema_version"]
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "schema_invalid"):
            ce._p4(data, SimpleNamespace(logon_id=LOGON, logical_processors=8), SHADOW)

    def test_old_strict_log_growth_gate_remains(self):
        data = p4_data(SHADOW)
        # The actual ending bounded inventory is unchanged; genuine growth
        # from a smaller initial size still fails the existing comparison.
        data["leak"]["idle_before"]["log_bytes"] -= 1
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "idle_growth_unresolved"):
            ce._p4(data, SimpleNamespace(logon_id=LOGON, logical_processors=8), SHADOW)


class OriginalReceiptObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.identities = {role: ProcessIdentity(8000 + index, 134343072000000001 + index, LOGON)
                           for index, role in enumerate(("helper", "guardian", "supervisor"))}

    def sink(self, role="helper", **kwargs):
        return log.ResidentTelemetry(data_dir=self.path, role=role, identity=self.identities[role],
            instance_id=f"00000000-0000-4000-8000-{self.identities[role].pid:012x}", **kwargs)

    def observation(self, sink, sequence=1):
        status, offers, writes = sink.observe()
        return NativeTelemetryObservation(sink.role, sink.identity, sink.instance_id, "1" * 32,
                                          sequence, sequence, status, offers, writes)

    def trace(self):
        return CohortTelemetryTrace(scope_nonce="1" * 32, identities=self.identities)

    def test_offer_ring_records_exact_supersession_without_persistence(self):
        sink = self.sink()
        first = sink.offer({"event": "helper_host_metrics"})
        second = sink.offer({"event": "helper_host_metrics", "value": 2})
        status, offers, writes = sink.observe()
        self.assertEqual(offers, (first, second))
        self.assertEqual(second.superseded, first.sequence)
        self.assertEqual(status["persisted"], 0)
        self.assertEqual(status["coalesced"], 1)
        self.assertEqual(writes, ())

    def test_ring_overwrite_is_explicit_coverage_loss(self):
        sink = self.sink()
        for _ in range(129):
            sink.offer({"event": "helper_host_metrics"})
        status, offers, _ = sink.observe()
        self.assertEqual(len(offers), 128)
        self.assertEqual(offers[0].sequence, 2)
        with self.assertRaisesRegex(TelemetryEvidenceError, "coverage_lost"):
            self.trace().add(self.observation(sink))

    def test_queued_report_has_no_disk_side_effect_in_observer_path(self):
        sink = self.sink()
        with patch.object(sink.store, "inventory", side_effect=AssertionError("disk read")), \
                patch.object(sink.store, "append", side_effect=AssertionError("disk write")):
            sink.offer({"event": "helper_host_metrics"})
            self.assertEqual(sink.observe()[0]["persisted"], 0)
        self.assertFalse(sink.store.directory.exists())

    def test_replayed_or_wrong_peer_observation_refused(self):
        sink, trace = self.sink(), self.trace()
        value = self.observation(sink)
        trace.add(value)
        with self.assertRaisesRegex(TelemetryEvidenceError, "replayed"):
            trace.add(value)
        with self.assertRaisesRegex(TelemetryEvidenceError, "peer_binding_invalid"):
            self.trace().add(replace(value, scope_nonce="2" * 32))

    def test_receipt_replacement_is_not_accepted_as_same_sequence(self):
        sink, trace = self.sink(), self.trace()
        sink.offer({"event": "helper_host_metrics"})
        trace.add(self.observation(sink))
        newer = self.observation(sink, 2)
        with self.assertRaisesRegex(TelemetryEvidenceError, "receipt_changed"):
            trace.add(replace(newer, offers=(replace(newer.offers[0], serialized_bytes=1),)))

    def test_duplicate_ring_reads_neither_reserialize_nor_charge_again(self):
        sink, trace = self.sink(), self.trace()
        sink.offer({"event": "helper_host_metrics"})
        trace.add(self.observation(sink))
        charged = trace._charged_bytes
        with patch.object(observed, "_encoded_size", side_effect=AssertionError("history serialized again")):
            trace.add(self.observation(sink, 2))
        self.assertEqual(trace._charged_bytes, charged)

    def test_full_inventory_receipts_hit_real_byte_cap_before_retention(self):
        # Explicit synthetic large-schema fixture. It is not source provenance
        # or a prefilled native measurement; only early allocation refusal.
        sink, trace = self.sink(), self.trace()
        value = self.observation(sink)
        now = 1_800_000_000_000_000_000
        inventory = tuple(log.ChunkObservation(f"event-{now:020d}-{index:032x}.jsonl",
            1024, now, "event", ((1 << 64) - 1, (1 << 100) + index)) for index in range(63))
        offers, writes = [], []
        for index in range(128):
            seq = index + 1
            before = inventory
            inventory = (*before[:-1], replace(before[-1], size=before[-1].size + 512))
            offers.append(log.EmitReceipt(sink.instance_id, seq, True, 512,
                                           "telemetry_queued", "event", None))
            writes.append(log.WriteReceipt(sequence=seq, first_offer=seq, last_offer=seq,
                records=1, written_bytes=512, deleted_bytes=0,
                before_bytes=1 + sum(item.size for item in before),
                after_bytes=1 + sum(item.size for item in inventory), deleted=(),
                inventory=inventory, utc_ns=now + index, offers=((seq, 512),),
                before_inventory=before, lock_identity=((1 << 64) - 1, (1 << 128) - 1), kind="event"))
        status = {**value.status, "offered": 128, "accepted": 128, "persisted": 128,
                  "written_bytes": 128 * 512, "inventory_bytes": 1 + sum(item.size for item in inventory)}
        large = replace(value, status=status, offers=tuple(offers), writes=tuple(writes))
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_byte_bound"):
            trace.add(large)
        self.assertLess(len(trace.rows["helper"]["writes"]), len(writes))
        self.assertLessEqual(trace._charged_bytes, ce._P4_MAX_BYTES)
        self.assertEqual(trace.MAX_TRACE_BYTES, ce._P4_MAX_BYTES)
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_unresolved"):
            trace.finish(((1 << 64) - 1, (1 << 128) - 1), inventory)
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_unresolved"):
            trace.add(replace(value, sequence=2, observed_tick=2))

    def test_rejected_new_offer_poison_prevents_partial_success(self):
        sink, trace = self.sink(), self.trace()
        sink.offer({"event": "helper_host_metrics"})
        trace._charged_bytes = trace.MAX_TRACE_BYTES - 1  # bounded near-limit fixture
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_byte_bound"):
            trace.add(self.observation(sink))
        self.assertEqual(trace.rows["helper"]["offers"], {})
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_unresolved"):
            trace.finish((1, 2), ())

    def test_poison_keeps_no_rejected_payload_through_exception_traceback(self):
        sink, trace = self.sink(), self.trace()
        class LargeRejectedPayload:
            pass
        def submit_and_discard_caller_exception():
            payload = LargeRejectedPayload()
            payload.padding = "x" * 100000
            reference = weakref.ref(payload)
            value = self.observation(sink)
            try:
                trace.add(replace(value, status={**value.status, "unexpected": payload}))
            except TelemetryEvidenceError as error:
                self.assertEqual(str(error), "p4_telemetry_degraded")
            return reference
        reference = submit_and_discard_caller_exception()
        gc.collect()
        self.assertIsNone(reference())
        self.assertEqual(trace._failure, ("TelemetryEvidenceError", "p4_telemetry_degraded"))
        self.assertTrue(all(type(item) is str and len(item) <= 128 for item in trace._failure))
        with self.assertRaisesRegex(TelemetryEvidenceError, "trace_unresolved"):
            trace.finish((1, 2), ())

    def test_unknown_framing_and_oversized_inventory_refuse_before_serialization(self):
        sink = self.sink()
        value = self.observation(sink)
        with patch.object(observed, "_encoded_size", side_effect=AssertionError("unbounded framing")):
            with self.assertRaisesRegex(TelemetryEvidenceError, "degraded"):
                self.trace().add(replace(value, status={**value.status, "extra": "x" * 10000}))
            with self.assertRaisesRegex(TelemetryEvidenceError, "receipt_invalid"):
                self.trace().finish((1, 2), (None,) * 64)

    def test_per_trace_bound_never_enlarges_whole_artifact_limit(self):
        from tests.windows.adaptive_capability_runner import _write_new
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "P4-data.json"
            with self.assertRaisesRegex(Exception, "too large|oversized"):
                _write_new(target, {"scope_a": "x" * (ce._P4_MAX_BYTES // 2),
                                    "scope_b": "x" * (ce._P4_MAX_BYTES // 2)}, expected_gate="P4")
            self.assertFalse(target.exists())

    def test_actual_filesystem_receipts_round_trip_through_closed_verifier(self):
        now = [time.monotonic()]
        sinks = [self.sink(role, monotonic=lambda: now[0]) for role in self.identities]
        for sink in sinks:
            sink.start()
        try:
            for sink in sinks:
                sink.offer({"event": "fixture_start"}, kind=log.TelemetryKind.EVENT)
            now[0] += 31  # Explicit portable timing fixture; never native evidence.
            required = sinks[0].offer({"event": "helper_host_metrics"})
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if all(sink.snapshot()["persisted"] == (2 if index == 0 else 1)
                       for index, sink in enumerate(sinks)):
                    break
                time.sleep(.01)
            trace = self.trace()
            for sink in sinks:
                self.assertIsNone(sink.snapshot()["error"])
                trace.add(self.observation(sink))
            lock, inventory = sinks[0].store.inventory_observation()
            value = trace.finish(lock, inventory)
            size = ce._p4_telemetry(value, SimpleNamespace(logon_id=LOGON),
                reports=[(required.sequence, required.serialized_bytes)])
            self.assertEqual(size, sum(item.stat().st_size for item in sinks[0].store.directory.iterdir()))
        finally:
            for sink in sinks:
                sink.request_stop()
            for sink in sinks:
                sink.finish()
                if sink._thread.is_alive():
                    sink._thread.join(3)
                self.assertFalse(sink._thread.is_alive())

    def test_generic_callback_or_native_boolean_cannot_create_probe(self):
        with self.assertRaisesRegex(TelemetryEvidenceError, "original_resident_telemetry_required"):
            NativeTelemetryProbe(SimpleNamespace(native=True), scope_nonce="1" * 32,
                                 log_directory=self.path)


if __name__ == "__main__":
    unittest.main()
