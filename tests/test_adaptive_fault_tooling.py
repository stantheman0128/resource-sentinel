"""Portable tests for the section 9 fault record and the fault coverage map."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from tests.fixtures.adaptive_fault_matrix import (
    FAULT_MATRIX, FaultMatrixError, FaultRow, SECTION_NINE_ROWS, TestEvidence, UNVERIFIED,
    render_markdown,
)
from tests.fixtures.adaptive_fault_record import (
    LIVE_DATA_DIRECTORY, FaultRecord, FaultRecordError, snapshot_ledger, write_fault_record,
)

IDENTITY = {"pid": 4321, "created_filetime_100ns": "133700000000000000"}


def _record(**overrides):
    fields = {
        "injection_point": "guardian_crash_after_durable_intent",
        "evidence_level": "L1",
        "state_before": {"mode": "shadow", "applied_rate_bp": None},
        "execution_identities": (IDENTITY,),
        "os_readback": {},
        "reservation_retained": True,
        "exemption_rows": ({"lease_id": "a", "expires_at": 1.5},),
        "exemption_revision": 7,
        "timestamps": {"injected_at": 10.0, "observed_at": 11.25},
        "final_reason": "restore_unverified_barrier_held",
    }
    fields.update(overrides)
    return FaultRecord(**fields)


class FaultRecordTests(unittest.TestCase):
    def test_complete_record_keeps_every_section_nine_field(self):
        record = _record()
        payload = record.to_dict()
        self.assertEqual(set(payload), {
            "injection_point", "evidence_level", "native", "state_before",
            "execution_identities", "os_readback", "reservation_retained",
            "exemption_rows", "exemption_revision", "timestamps", "final_reason"})
        self.assertEqual(payload["execution_identities"], [IDENTITY])
        self.assertEqual(payload["exemption_revision"], 7)
        self.assertEqual(json.loads(json.dumps(payload))["final_reason"],
                         "restore_unverified_barrier_held")

    def test_native_is_derived_from_the_level_and_cannot_be_set(self):
        self.assertFalse(_record().native)
        self.assertTrue(_record(evidence_level="L2", os_readback={"flags": 0}).native)
        with self.assertRaises(TypeError):
            FaultRecord(native=True, **{})

    def test_level_and_readback_must_agree(self):
        with self.assertRaises(FaultRecordError):
            _record(evidence_level="L2")
        with self.assertRaises(FaultRecordError):
            _record(os_readback={"flags": 0})
        with self.assertRaises(FaultRecordError):
            _record(evidence_level="L5")

    def test_missing_or_malformed_section_nine_fields_are_refused(self):
        for overrides in (
            {"injection_point": "  "},
            {"state_before": {}},
            {"execution_identities": ()},
            {"execution_identities": ({"pid": 0, "created_filetime_100ns": "1"},)},
            {"execution_identities": ({"pid": 5, "created_filetime_100ns": 5},)},
            {"reservation_retained": 1},
            {"exemption_revision": -1},
            {"timestamps": {}},
            {"timestamps": {"injected_at": float("inf")}},
            {"final_reason": ""},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(FaultRecordError):
                _record(**overrides)

    def test_record_is_frozen(self):
        record = _record()
        with self.assertRaises(Exception):
            record.final_reason = "other"


class BoundedWriterTests(unittest.TestCase):
    def test_writes_bounded_json_and_refuses_an_oversized_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "fault.json"
            written = write_fault_record(path, _record())
            self.assertGreater(written, 0)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["native"], False)
            self.assertFalse(list(path.parent.glob("*.pending")))
            with self.assertRaises(FaultRecordError):
                write_fault_record(path, _record(), max_bytes=32)

    def test_refuses_a_relative_path_and_the_live_data_directory(self):
        with self.assertRaises(FaultRecordError):
            write_fault_record(Path("fault.json"), _record())
        with self.assertRaises(FaultRecordError):
            write_fault_record(LIVE_DATA_DIRECTORY / "evidence" / "fault.json", _record())


class LedgerSnapshotTests(unittest.TestCase):
    def _ledger(self, directory, rows):
        path = Path(directory).resolve() / "isolated.db"
        connection = sqlite3.connect(path)
        try:
            connection.execute("CREATE TABLE reservations (id TEXT, units REAL)")
            connection.execute("CREATE TABLE grants (id TEXT, revision INTEGER)")
            connection.executemany("INSERT INTO reservations VALUES (?, ?)", rows)
            connection.execute("INSERT INTO grants VALUES ('g1', 3)")
            connection.commit()
        finally:
            connection.close()
        return path

    def test_snapshots_named_tables_before_and_after(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._ledger(directory, [("r1", 2.0)])
            before = snapshot_ledger(path, ("reservations", "grants"))
            self.assertEqual(dict(before["reservations"][0]), {"id": "r1", "units": 2.0})
            self.assertEqual(dict(before["grants"][0]), {"id": "g1", "revision": 3})
            connection = sqlite3.connect(path)
            try:
                connection.execute("INSERT INTO reservations VALUES ('r2', 1.0)")
                connection.commit()
            finally:
                connection.close()
            after = snapshot_ledger(path, ("reservations",))
            self.assertEqual(len(before["reservations"]), 1)
            self.assertEqual(len(after["reservations"]), 2)

    def test_snapshot_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._ledger(directory, [("r1", 2.0)])
            before = path.stat().st_mtime_ns
            snapshot = snapshot_ledger(path, ("reservations",))
            with self.assertRaises(TypeError):
                snapshot["reservations"][0]["id"] = "changed"
            with self.assertRaises(TypeError):
                snapshot["reservations"] = ()
            self.assertEqual(path.stat().st_mtime_ns, before)

    def test_bounds_rows_and_rejects_unknown_or_unsafe_names(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._ledger(directory, [(f"r{index}", float(index)) for index in range(5)])
            with self.assertRaises(FaultRecordError):
                snapshot_ledger(path, ("reservations",), max_rows=4)
            self.assertEqual(len(snapshot_ledger(path, ("reservations",), max_rows=5)["reservations"]), 5)
            with self.assertRaises(FaultRecordError):
                snapshot_ledger(path, ("absent",))
            with self.assertRaises(FaultRecordError):
                snapshot_ledger(path, ('reservations"; DROP TABLE grants;--',))
            with self.assertRaises(FaultRecordError):
                snapshot_ledger(path, ())

    def test_refuses_the_live_data_directory_and_missing_files(self):
        with self.assertRaises(FaultRecordError):
            snapshot_ledger(LIVE_DATA_DIRECTORY / "sentinel.db", ("reservations",))
        with self.assertRaises(FaultRecordError):
            snapshot_ledger(LIVE_DATA_DIRECTORY / "nested" / "sentinel.db", ("reservations",))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FaultRecordError):
                snapshot_ledger(Path(directory).resolve() / "absent.db", ("reservations",))


class FaultMatrixTests(unittest.TestCase):
    def test_every_section_nine_row_has_exactly_one_entry(self):
        self.assertEqual(tuple(FAULT_MATRIX), tuple(id_ for id_, _ in SECTION_NINE_ROWS))
        for fault_id, label in SECTION_NINE_ROWS:
            self.assertEqual(FAULT_MATRIX[fault_id].fault, label)

    def test_every_referenced_test_id_exists_in_the_tree(self):
        for row in FAULT_MATRIX.values():
            for evidence in row.evidence:
                with self.subTest(test_id=evidence.test_id):
                    self.assertTrue(callable(evidence.resolve()))

    def test_unverified_rows_state_a_reason_and_claim_no_evidence(self):
        unverified = [row for row in FAULT_MATRIX.values() if row.status == UNVERIFIED]
        self.assertTrue(unverified)
        for row in unverified:
            self.assertEqual(row.evidence, ())
            self.assertGreater(len(row.unverified_reason), 20)

    def test_status_names_the_evidence_level_so_portable_rows_never_read_as_native(self):
        portable = TestEvidence("tests.module.Class.test_x", "L1")
        native = TestEvidence("tests.windows.module.Class.test_x", "L3")
        self.assertEqual(FaultRow("id", "label", (portable,)).status, "L1_ONLY")
        self.assertEqual(FaultRow("id", "label", (portable, native)).status, "NATIVE_L3")
        for row in FAULT_MATRIX.values():
            self.assertIn(row.status, (UNVERIFIED, "L1_ONLY"))

    def test_a_portable_test_cannot_be_native_evidence(self):
        with self.assertRaises(FaultMatrixError):
            TestEvidence("tests.test_adaptive_ipc.FramingTests.test_x", "L2")
        self.assertEqual(
            TestEvidence("tests.windows.test_adaptive_job_capability."
                         "WindowsJobCapabilitySpike.test_x", "L2").level, "L2")

    def test_malformed_ids_and_rows_are_refused(self):
        for test_id in ("FramingTests.test_x", "tests.module.lowercase.test_x",
                        "tests.module.Class.helper", "other.module.Class.test_x"):
            with self.subTest(test_id=test_id), self.assertRaises(FaultMatrixError):
                TestEvidence(test_id, "L1")
        with self.assertRaises(FaultMatrixError):
            TestEvidence("tests.module.Class.test_x", "L9")
        with self.assertRaises(FaultMatrixError):
            FaultRow("id", "label")
        with self.assertRaises(FaultMatrixError):
            FaultRow("id", "label", (TestEvidence("tests.m.C.test_x", "L1"),), "reason")

    def test_unresolvable_test_id_fails_loudly(self):
        with self.assertRaises(FaultMatrixError):
            TestEvidence("tests.test_adaptive_ipc.FramingTests.test_absent", "L1").resolve()
        with self.assertRaises(FaultMatrixError):
            TestEvidence("tests.test_absent_module.Tests.test_x", "L1").resolve()

    def test_markdown_renders_one_line_per_row(self):
        rendered = render_markdown()
        lines = rendered.splitlines()
        self.assertEqual(len(lines), len(SECTION_NINE_ROWS) + 2)
        self.assertIn("| Fault | Status | Evidence | Level | Reason / gap |", lines[0])
        self.assertIn(UNVERIFIED, rendered)
        for _, label in SECTION_NINE_ROWS:
            self.assertIn(f"| {label} |", rendered)


if __name__ == "__main__":
    unittest.main()
