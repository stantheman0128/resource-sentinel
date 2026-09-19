"""Pure S3 evidence arithmetic; these tests do not establish Windows recovery."""
import unittest

from tests.windows.test_adaptive_recovery_capability import (
    TICKS_PER_SECOND, guardian_restore_timing, observation_timing,
)


def restored(seconds, *, flags=0):
    return {"interrupt_tick_100ns": str(round(seconds * TICKS_PER_SECOND)),
            "result": "RESTORED", "after": {"flags": flags, "rate_bp": 10000}}


class RecoveryTimingEvidenceTests(unittest.TestCase):
    def test_late_observer_cannot_restart_guardian_loss_clock(self):
        # Observer resumes at 30s after a 10s restoration. Its wake time must not
        # turn the real 10s bound into a near-zero passing measurement.
        timing = guardian_restore_timing({"interrupt_tick_100ns": "0"}, [restored(10)])
        self.assertEqual(timing["upper_bound_seconds"], 10)
        self.assertFalse(timing["within_8_seconds"])

    def test_exact_eight_seconds_passes_but_one_tick_later_fails(self):
        anchor = {"interrupt_tick_100ns": "0"}
        self.assertTrue(guardian_restore_timing(anchor, [restored(8)])["within_8_seconds"])
        late = restored(8)
        late["interrupt_tick_100ns"] = str(8 * TICKS_PER_SECOND + 1)
        self.assertFalse(guardian_restore_timing(anchor, [late])["within_8_seconds"])

    def test_first_verified_readback_is_endpoint_not_late_second_contender(self):
        result = guardian_restore_timing({"interrupt_tick_100ns": "0"},
                                         [restored(11), restored(7)])
        self.assertEqual(result["upper_bound_seconds"], 7)

    def test_forced_stop_uses_request_before_termination_not_marker_publish(self):
        anchor = {"termination_requested_tick_100ns": "0",
                  "interrupt_tick_100ns": str(20 * TICKS_PER_SECOND)}
        result = guardian_restore_timing(anchor, [restored(10)],
                                         anchor_field="termination_requested_tick_100ns")
        self.assertFalse(result["within_8_seconds"])

    def test_unknown_invalid_or_reversed_evidence_is_not_a_pass(self):
        for anchor in ({}, {"interrupt_tick_100ns": None},
                       {"interrupt_tick_100ns": 0}, {"interrupt_tick_100ns": "-1"},
                       {"interrupt_tick_100ns": "NaN"}, {"interrupt_tick_100ns": "1.5"},
                       {"interrupt_tick_100ns": str(2**64)}):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                guardian_restore_timing(anchor, [restored(7)])
        with self.assertRaises(ValueError):
            guardian_restore_timing({"interrupt_tick_100ns": str(8 * TICKS_PER_SECOND)},
                                     [restored(7)])
        with self.assertRaises(ValueError):
            guardian_restore_timing({"interrupt_tick_100ns": "0"}, [])
        with self.assertRaises(ValueError):
            guardian_restore_timing({"interrupt_tick_100ns": "0"},
                                     [restored(7), {"result": "RESTORED", "after": {"flags": 0}}])

    def test_enabled_or_unverified_ack_cannot_supply_timing_endpoint(self):
        for record in (restored(1, flags=5), restored(1, flags=False),
                       {**restored(1), "result": "UNVERIFIED"}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                guardian_restore_timing({"interrupt_tick_100ns": "0"}, [record])

    def test_observation_reaches_120_seconds_is_failure_including_cleanup(self):
        self.assertTrue(observation_timing(0, 119 * TICKS_PER_SECOND, 119)["within_deadline"])
        self.assertFalse(observation_timing(0, 120 * TICKS_PER_SECOND, 120)["within_deadline"])
        self.assertFalse(observation_timing(0, 121 * TICKS_PER_SECOND, 121)["within_deadline"])

    def test_either_observation_clock_exceeding_deadline_rejects(self):
        self.assertFalse(observation_timing(0, 121 * TICKS_PER_SECOND, 1)["within_deadline"])
        self.assertFalse(observation_timing(0, TICKS_PER_SECOND, 121)["within_deadline"])

    def test_unknown_observation_time_cannot_pass(self):
        for args in ((1, 0, 1), (0, 1, float("nan")), (0, 1, float("inf")),
                     (0, 1, -1), (0, 1, True), (0, None, 1), (0, 2**64, 1)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                observation_timing(*args)


if __name__ == "__main__":
    unittest.main()
