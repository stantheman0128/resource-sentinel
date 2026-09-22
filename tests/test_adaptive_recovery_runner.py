"""Portable S3 reducer/custody tests; synthetic records prove no native gate."""
from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from tests.windows import adaptive_recovery_runner as runner


RUN = "61c69f2d-ded8-49c0-8320-912633c346bf"
EXECUTION = "95a9131d-eedc-493e-8839-a6820e2eed5e"
TICK = runner.TICKS_PER_SECOND


def evidence(case="set_after_query_before"):
    spec = runner.CaseSpec(RUN, case, 1, "a" * 32, TICK)
    def record(event, seconds, **values):
        return dict(run_id=RUN, case=case, iteration=1, scope_nonce="a" * 32,
                    event=event, tick=seconds * TICK, **values)
    observations = [record("native_query", 2, execution_id=EXECUTION, job_nonce="b" * 32,
        cpu_flags=5, active_processes=2, direct_allocations=1, routed_allocations=0,
        archive_outcomes=[], slot={"slot_state": "HELD", "execution_id": EXECUTION}),
        record("native_query", 5, execution_id=EXECUTION, job_nonce="b" * 32,
        cpu_flags=0, active_processes=1, direct_allocations=1, routed_allocations=0,
        archive_outcomes=[], slot={"slot_state": "RESTORED", "execution_id": EXECUTION})]
    events = [record("instrumentation_ready", 2, native_writers=["guardian", "retained_supervisor"]),
              record("fault_injected", 3, point=case, execution_id=EXECUTION, job_nonce="b" * 32),
              record("fault_observed", 4),
              record("cpu_write", 2, before_tick=TICK + 1, execution_id=EXECUTION,
                     job_nonce="b" * 32, desired_flags=5, desired_rate_bp=2500, attempt_id="first")]
    events.append(dict(events[-1], event="cpu_write_attempt", tick=TICK + 1))
    cleanup = dict.fromkeys(("cpu_flags", "active_processes", "pending_intents",
                            "unsettled_handles", "live_allocations"), 0)
    return spec, observations, events, cleanup


class RecoveryReducerTests(unittest.TestCase):
    def reduce(self, data, ended=6 * TICK):
        spec, observations, events, cleanup = data
        return runner.reduce_case(spec, observations=observations, events=events,
                                  cleanup=cleanup, ended_tick=ended)

    def test_original_fault_and_disabled_live_child_are_distinct_observations(self):
        value = self.reduce(evidence())
        self.assertEqual(value["observations"]["remaining_members_before_stop"], 1)
        self.assertEqual(value["observations"]["fault_tick"], 3 * TICK)
        self.assertEqual(value["observations"]["disabled_query_tick"], 5 * TICK)
        self.assertEqual(value["cleanup"]["unsettled_handles"], 0)

    def test_missing_fault_effect_cannot_be_assumed_from_request(self):
        data = evidence()
        data[2][:] = [row for row in data[2] if row["event"] != "fault_observed"]
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "effect_unverified"):
            self.reduce(data)

    def test_job_empty_or_query_before_death_does_not_prove_restore(self):
        for update in ({"active_processes": 0}, {"tick": 4 * TICK}, {"cpu_flags": 5}):
            data = evidence()
            data[1][-1].update(update)
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "restore_query_missing"):
                self.reduce(data)

    def test_single_fault_eight_second_bound_includes_detection_latency(self):
        data = evidence()
        next(row for row in data[2] if row["event"] == "fault_observed")["tick"] = 11 * TICK
        data[1][-1]["tick"] = 12 * TICK
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "too_slow"):
            self.reduce(data, ended=13 * TICK)

    def test_common_failure_claims_only_eventual_recovery(self):
        data = evidence("independent_supervisor_recovery")
        data[1][-1]["tick"] = 110 * TICK
        value = self.reduce(data, ended=111 * TICK)
        self.assertEqual(value["observations"]["disabled_query_tick"], 110 * TICK)

    def test_common_failure_cannot_extend_external_observation_deadline(self):
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "observation_deadline"):
            self.reduce(evidence("independent_supervisor_recovery"), ended=122 * TICK)

    def test_child_survival_keeps_exact_original_allocation(self):
        for update in ({"direct_allocations": 0}, {"routed_allocations": 1},
                       {"archive_outcomes": ["managed_finished"]}):
            data = evidence()
            data[1][-1].update(update)
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
                self.reduce(data)

    def test_foreign_slot_and_scope_are_not_filtered_out(self):
        data = evidence()
        data[1][0]["slot"]["execution_id"] = RUN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "foreign_control_slot"):
            self.reduce(data)
        data = evidence()
        data[1][0]["job_nonce"] = "f" * 32
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "scope_binding_changed"):
            self.reduce(data)

    def test_replayed_run_event_is_rejected(self):
        data = evidence()
        data[2][-1]["run_id"] = EXECUTION
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "binding_changed"):
            self.reduce(data)

    def test_fault_on_other_job_cannot_borrow_disabled_query(self):
        data = evidence()
        next(row for row in data[2] if row["event"] == "fault_injected")["job_nonce"] = "c" * 32
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "fault_scope_mismatch"):
            self.reduce(data)

    def test_already_disabled_job_with_no_original_set_is_not_recovery(self):
        data = evidence()
        data[1][0]["cpu_flags"] = 0
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "initial_native_set_unverified"):
            self.reduce(data)

    def test_fault_before_set_does_not_require_a_cap_that_was_never_applied(self):
        data = evidence("intent_after_set_before")
        data[1][0]["cpu_flags"] = 0
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        self.assertEqual(self.reduce(data)["observations"]["disabled_flags"], 0)

    def test_grant_commit_cannot_be_followed_by_a_new_restriction(self):
        data = evidence("grant_before_cap")
        data[2].append(dict(data[2][0], event="exemption_commit_observed", tick=TICK + 1,
                           execution_id=EXECUTION, job_nonce="b" * 32))
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "restriction_after_exemption"):
            self.reduce(data)
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        data[1][0]["cpu_flags"] = 0
        self.assertEqual(self.reduce(data)["observations"]["disabled_flags"], 0)

    def test_missing_writer_instrumentation_is_unknown_not_zero(self):
        data = evidence()
        data[2].pop(0)
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "instrumentation_missing"):
            self.reduce(data)

    def test_overlapping_writers_and_foreign_writes_fail(self):
        data = evidence()
        event = dict(data[2][0], event="cpu_write", before_tick=2 * TICK,
                     tick=3 * TICK, execution_id=EXECUTION, job_nonce="b" * 32,
                     attempt_id="second", desired_flags=0, desired_rate_bp=10000)
        other = dict(event, before_tick=2 * TICK + 1, attempt_id="third")
        data[2].extend((dict(event, event="cpu_write_attempt", tick=event["before_tick"]), event,
                       dict(other, event="cpu_write_attempt", tick=other["before_tick"]), other))
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
            self.reduce(data)
        del data[2][-2:]
        data[2][-1]["execution_id"] = data[2][-2]["execution_id"] = RUN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
            self.reduce(data)

    def test_fault_termination_of_workload_or_pid_only_target_is_not_recovery(self):
        for role, verified in (("workload", True), ("guardian", False)):
            data = evidence()
            data[2].append(dict(data[2][-1], event="process_fault_termination", role=role,
                               original_creation_handle_verified=verified))
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
                self.reduce(data)

    def test_uncertain_or_missing_set_completion_invalidates_evidence(self):
        for missing in (True, False):
            data = evidence()
            completion = next(row for row in data[2] if row["event"] == "cpu_write")
            if missing:
                data[2].remove(completion)
            else:
                completion["event"] = "cpu_write_unknown"
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "instrumentation_unverified"):
                self.reduce(data)

    def test_cleanup_missing_field_false_or_nonzero_never_passes(self):
        for invalid in (None, False, 1):
            data = evidence()
            if invalid is None:
                del data[3]["unsettled_handles"]
            else:
                data[3]["unsettled_handles"] = invalid
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "cleanup_unverified"):
                self.reduce(data)

    def test_original_case_bounds_and_boolean_timestamp(self):
        for iteration in (0, 11, True):
            with self.assertRaises(runner.RecoveryRunUnavailable):
                runner.CaseSpec(RUN, "intent_before", iteration, "a" * 32, TICK)
        with self.assertRaises(runner.RecoveryRunUnavailable):
            runner.CaseSpec(RUN, "intent_before", 1, "a" * 32, True)


class RawRecoveryLogTests(unittest.TestCase):
    def test_log_is_bounded_bound_and_new_only(self):
        spec = evidence()[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            log = runner.RawEvents(spec, path)
            value = log.append("fault_observed", tick=4 * TICK)
            self.assertEqual(runner.read_actor_events(path, spec), [value])
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "already_exists"):
                runner.RawEvents(spec, path)
            with patch.object(runner, "MAX_EVENTS", 1):
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "limit"):
                    log.append("fault_observed", tick=5 * TICK)

    def test_partial_record_cannot_be_used_as_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            path.write_bytes(b'{"tick":5}')
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "incomplete"):
                runner.read_actor_events(path, evidence()[0])

    def test_immutable_artifact_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            runner.write_new(path, {"status": "failed"})
            with self.assertRaises(FileExistsError):
                runner.write_new(path, {"status": "passed"})


class ActorCustodyTests(unittest.TestCase):
    def actors(self):
        actor = object.__new__(subprocess.Popen)
        actor.pid, actor.returncode = 100, None
        actor._child_created = False
        actor._handle = Mock()
        actor.poll = Mock(return_value=None)
        witness = object.__new__(VerifiedProcess)
        witness._identity = ProcessIdentity(100, 900, "S-1-5-5-1-2")
        witness.observe = Mock(return_value=SimpleNamespace(identity=witness.identity, status=IdentityStatus.ALIVE))
        witness.close = Mock()
        return actor, witness

    def test_live_actor_prevents_positive_cleanup_and_never_closes(self):
        actor, witness = self.actors()
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        self.assertFalse(custody.settle_exited())
        witness.close.assert_not_called()
        actor._handle.Close.assert_not_called()

    def test_verified_native_death_and_original_popen_exit_close_once(self):
        actor, witness = self.actors()
        actor.poll.return_value = 0
        witness.observe.return_value.status = IdentityStatus.DEAD
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        self.assertTrue(custody.settle_exited())
        self.assertTrue(custody.settle_exited())
        witness.close.assert_called_once()
        actor._handle.Close.assert_called_once()

    def test_unknown_close_quarantines_without_reclose(self):
        actor, witness = self.actors()
        actor.poll.return_value = 0
        witness.observe.return_value.status = IdentityStatus.DEAD
        witness.close.side_effect = KeyboardInterrupt()
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        with self.assertRaises(KeyboardInterrupt):
            custody.settle_exited()
        self.assertFalse(custody.settle_exited())
        witness.close.assert_called_once()
        actor._handle.Close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
