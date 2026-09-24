"""Strict probe-completion history data; synthetic tuples are not native proof."""
from copy import deepcopy
import json
import unittest

from sentinel.adaptive import experiment_history as history
from tests import test_adaptive_experiment_history as history_fixture


class ExperimentProbeHistoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = history_fixture.ExperimentHistoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def record(self, kind="FINISHED", outcomes=("opened_closed", "opened_closed")):
        record = self.fixture.native_record(kind)
        record["completion"].update(schema_version=2,
            probe_custody=[dict(ordinal=index, outcome=outcome)
                           for index, outcome in enumerate(outcomes, 1)])
        return self.fixture.rehash(record)

    def reject(self, record):
        with self.assertRaises(history.ExperimentHistoryError):
            history.canonical_receipt(self.fixture.rehash(record))

    def test_original_v1_shapes_still_validate_in_actual_history_reader(self):
        for kind in sorted(history.DISPOSITIONS):
            with self.subTest(kind=kind):
                record = (deepcopy(self.fixture.record) if kind == "BEFORE_NATIVE"
                          else self.fixture.native_record(kind))
                encoded, _ = history.canonical_receipt(record)
                result = history.verify_experiment_history_locked(self.fixture.database(record))
                self.assertEqual(result.receipts_json, (encoded,))
                self.assertEqual(json.loads(encoded)["completion"]["schema_version"], 1)

    def test_registered_v2_closed_probe_sequences_are_read_only_history(self):
        for kind in ("NEVER_LAUNCHED", "FINISHED"):
            for outcomes in (("opened_closed",), ("failed_closed",),
                             ("opened_closed", "opened_closed"),
                             ("opened_closed", "failed_closed"),
                             ("failed_closed", "opened_closed"),
                             ("failed_closed", "failed_closed")):
                with self.subTest(kind=kind, outcomes=outcomes):
                    record = self.record(kind, outcomes)
                    encoded, _ = history.canonical_receipt(record)
                    conn = self.fixture.database(record)
                    before = conn.total_changes
                    result = history.verify_experiment_history_locked(conn)
                    self.assertEqual(result.receipts_json, (encoded,))
                    self.assertEqual(conn.total_changes, before)
                    self.assertEqual(result.completed_execution_ids,
                                     frozenset({record["execution_id"]}))

    def test_probe_version_requires_exact_supported_integer(self):
        for version in (True, False, 2.0, "2", 0, 3, None):
            with self.subTest(version=version):
                record = self.record()
                record["completion"]["schema_version"] = version
                self.reject(record)

    def test_early_dispositions_cannot_claim_probe_custody(self):
        for kind in ("BEFORE_NATIVE", "PREPARATION_CLOSED", "WRAPPER_NOT_CREATED"):
            with self.subTest(kind=kind):
                record = (deepcopy(self.fixture.record) if kind == "BEFORE_NATIVE"
                          else self.fixture.native_record(kind))
                record["completion"].update(schema_version=2,
                    probe_custody=[dict(ordinal=1, outcome="opened_closed")])
                self.reject(record)

    def test_v1_cannot_smuggle_probes_and_v2_requires_its_exact_field(self):
        record = self.record()
        record["completion"]["schema_version"] = 1
        self.reject(record)
        record = self.record()
        del record["completion"]["probe_custody"]
        self.reject(record)
        record = self.record()
        record["completion"]["unknown"] = 1
        self.reject(record)

    def test_probe_list_has_one_or_two_concrete_entries_only(self):
        entry = dict(ordinal=1, outcome="opened_closed")
        for value in ([], None, {}, "closed", [entry, entry, entry], [None], [[]]):
            with self.subTest(value=value):
                record = self.record()
                record["completion"]["probe_custody"] = value
                self.reject(record)

    def test_ordinals_are_exact_contiguous_and_entry_shape_is_closed(self):
        for entries in (
                [dict(ordinal=True, outcome="opened_closed")],
                [dict(ordinal=1.0, outcome="opened_closed")],
                [dict(ordinal="1", outcome="opened_closed")],
                [dict(ordinal=0, outcome="opened_closed")],
                [dict(ordinal=2, outcome="opened_closed")],
                [dict(ordinal=1, outcome="opened_closed"), dict(ordinal=1, outcome="failed_closed")],
                [dict(ordinal=1, outcome="opened_closed"), dict(ordinal=3, outcome="failed_closed")],
                [dict(ordinal=1, outcome="opened_closed", handle=99)],
                [dict(ordinal=1)], [dict(outcome="opened_closed")]):
            with self.subTest(entries=entries):
                record = self.record()
                record["completion"]["probe_custody"] = entries
                self.reject(record)

    def test_only_positive_original_close_outcomes_are_valid_data(self):
        for outcome in ("opened", "live", "unknown", "close_unknown", "not_attempted",
                        "closed", "failed", "", 1, True, None, {}):
            with self.subTest(outcome=outcome):
                record = self.record(outcomes=(outcome,))
                self.reject(record)

    def test_closure_digest_covers_probe_history_and_no_version_downgrade(self):
        for action in ("change", "remove", "downgrade"):
            with self.subTest(action=action):
                record = self.record()
                if action == "change":
                    record["completion"]["probe_custody"][0]["outcome"] = "failed_closed"
                elif action == "remove":
                    record["completion"]["probe_custody"].pop()
                else:
                    record["completion"]["schema_version"] = 1
                    del record["completion"]["probe_custody"]
                # Deliberately preserve the old digest; rehashing here would
                # test valid synthetic data, not tampering with that record.
                with self.assertRaisesRegex(history.ExperimentHistoryError, "completion_digest_changed"):
                    history.canonical_receipt(record)


if __name__ == "__main__":
    unittest.main()
