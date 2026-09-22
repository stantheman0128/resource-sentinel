"""Portable P6 sequencing tests with explicit fabricated native collaborators.

No test measures Windows or produces release evidence. Measured-labelled test
records only exercise the coordinator's success branch; the native entry and
real daily provider are never replaced by a CLI or serialized override.
"""
from dataclasses import dataclass, replace
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from tests.benchmarks import adaptive_orchestrator as runner
from tests.benchmarks.adaptive_ab import CacheState, Comparison, EvidenceSource, NativeCapInterval, Variant
from tests.test_adaptive_ab import SEED, conditions, metrics, record


def registration(**changes):
    value = runner.MatrixRegistration(str(uuid4()), SEED, 10, (("source.py", "a" * 64),),
                                      "b" * 64, "c" * 64, "d" * 64)
    return replace(value, **changes)


class RegistrationTests(unittest.TestCase):
    def test_full_matrix_contains_420_distinct_comparisons_and_420_noise_runs(self):
        value = registration()
        episodes = runner.required_episodes(value)
        self.assertEqual(len(episodes), 840)
        self.assertEqual(len({item.run_id for item in episodes}), 840)
        self.assertEqual(sum(item.purpose is runner.EpisodePurpose.CALIBRATION for item in episodes), 420)
        self.assertEqual(sum(item.purpose is runner.EpisodePurpose.COMPARISON for item in episodes), 420)
        self.assertTrue(all(item.purpose is runner.EpisodePurpose.CALIBRATION for item in episodes[:420]))
        matrix = {(item.scenario.name, item.comparison) for item in episodes}
        self.assertEqual(len(matrix), 21)

    def test_run_identity_is_deterministic_only_within_same_registration(self):
        first = registration()
        self.assertEqual(runner.required_episodes(first), runner.required_episodes(first))
        second = replace(first, registration_id=str(uuid4()))
        self.assertFalse({item.run_id for item in runner.required_episodes(first)} &
                         {item.run_id for item in runner.required_episodes(second)})

    def test_comparison_runs_follow_the_seed_order_exactly(self):
        value = registration()
        episodes = [item for item in runner.required_episodes(value)
                    if item.purpose is runner.EpisodePurpose.COMPARISON]
        for slot, pair in zip(value.schedule.slots, zip(episodes[::2], episodes[1::2])):
            self.assertEqual(tuple(item.variant for item in pair), (slot.first_variant, slot.second_variant))
            self.assertTrue(all(item.pair_index == slot.pair_index and item.comparison is slot.comparison
                                and item.scenario.name == slot.scenario for item in pair))

    def test_complex_scenarios_have_real_scope_requirements_not_synthetic_metrics(self):
        values = {item.name: item for item in runner.SCENARIOS}
        mixed = values["mixed_exempt_background_protected"]
        self.assertEqual(mixed.managed_roles, ("background", "exempt", "protected"))
        self.assertTrue(mixed.requires_explicit_test_grant)
        self.assertEqual(mixed.task_count, 3)
        pressure = values["unmanaged_cpu_pressure"]
        self.assertEqual(pressure.unmanaged_workers, 4)
        self.assertEqual(pressure.task_count, 5)
        lifetime = values["mixed_root_and_child_durations"]
        self.assertLess(lifetime.root_seconds, max(lifetime.child_seconds))

    def test_bad_bounds_and_non_exact_version_are_rejected(self):
        for change in ({"pairs_per_scenario": 9}, {"pairs_per_scenario": 101},
                       {"pairs_per_scenario": True}, {"schema_version": True},
                       {"source_sha256": (("../secret", "a" * 64),)},
                       {"cache_state": "warm"}):
            with self.subTest(change=change), self.assertRaises(runner.MatrixUnavailable):
                registration(**change)

    def test_new_journal_preserves_registration_and_refuses_reuse(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "pass"
            journal = runner.MatrixJournal(directory, registration())
            journal.event("pass_started")
            self.assertTrue((directory / "registration.json").is_file())
            self.assertTrue((directory / "schedule.json").is_file())
            self.assertIn('"phase":"pass_started"', journal.path.read_text(encoding="utf-8"))
            with self.assertRaises(runner.MatrixUnavailable):
                runner.MatrixJournal(directory, registration())


class PerEpisodeSafetyTests(unittest.TestCase):
    def spec(self, scenario=0, variant=Variant.B):
        value = registration()
        return runner.episode_spec(value, Comparison.A1_B, runner.SCENARIOS[scenario], 0,
                                   variant, runner.EpisodePurpose.COMPARISON)

    def test_any_native_api_error_stops_next_episode(self):
        with self.assertRaisesRegex(runner.MatrixUnavailable, "native_api_errors"):
            runner.assert_episode_safety(self.spec(), replace(metrics(), api_errors=1))

    def test_unmanaged_control_coverage_is_reported_without_fabricating_enrollment(self):
        runner.assert_episode_safety(self.spec(4), replace(metrics(), coverage_fraction=0.0))

    def test_state_label_cannot_hide_recovering_baseline_cap(self):
        interval = NativeCapInterval("job", 10, 20, 5, 5000, "RECOVERING")
        for scenario, variant in ((1, Variant.B), (0, Variant.A1)):
            with self.subTest(scenario=scenario, variant=variant), self.assertRaisesRegex(
                    runner.MatrixUnavailable, "unrelated_native_cap"):
                runner.assert_episode_safety(self.spec(scenario, variant),
                                             replace(metrics(), native_cap_intervals=(interval,)))

    def test_overlapping_and_zero_length_second_victim_fail(self):
        left = NativeCapInterval("one", 10, 20, 5, 1000, "CAPPED_L1")
        for start, end in ((15, 25), (20, 20)):
            right = NativeCapInterval("two", start, end, 5, 1000, "CAPPED_L1")
            with self.subTest(start=start), self.assertRaisesRegex(runner.MatrixUnavailable, "multiple_native_victims"):
                runner.assert_episode_safety(self.spec(), replace(metrics(), native_cap_intervals=(left, right)))

    def test_disjoint_native_victims_are_not_simultaneous(self):
        intervals = (NativeCapInterval("one", 10, 20, 5, 1000, "CAPPED_L1"),
                     NativeCapInterval("two", 21, 30, 5, 1000, "CAPPED_L1"))
        runner.assert_episode_safety(self.spec(), replace(metrics(), native_cap_intervals=intervals))


class BaselineReturnTests(unittest.TestCase):
    def points(self, start, count):
        return tuple(runner.BaselinePoint("clock", "a" * 64,
            index * 1_000_000_000, (index + 1) * 1_000_000_000,
            .2, 20 << 30, 8 << 30, 8 << 30, True, True, True, "b" * 64)
            for index in range(start, start + count))

    def test_return_uses_actual_predeclared_cpu_and_commit_envelope(self):
        envelope = runner.BaselineEnvelope(self.points(0, 10))
        self.assertTrue(envelope.accepts(self.points(20, 5)))
        for changes in ({"cpu_units": .2001}, {"commit_used_bytes": (20 << 30) + 1}):
            current = list(self.points(20, 5))
            current[2] = replace(current[2], **changes)
            self.assertFalse(envelope.accepts(tuple(current)))

    def test_unknown_job_or_restore_state_cannot_mean_baseline(self):
        envelope = runner.BaselineEnvelope(self.points(0, 10))
        for field in ("prior_native_scopes_empty", "owned_caps_disabled", "original_custody_settled"):
            current = list(self.points(20, 5))
            current[0] = replace(current[0], **{field: None})
            with self.subTest(field=field), self.assertRaisesRegex(runner.MatrixUnavailable, "cleanup_unverified"):
                envelope.accepts(tuple(current))

    def test_reference_cannot_be_reset_from_a_later_changed_epoch(self):
        envelope = runner.BaselineEnvelope(self.points(0, 10))
        for changes in ({"clock_id": "new-clock"}, {"conditions_sha256": "c" * 64}):
            current = tuple(replace(point, **changes) for point in self.points(20, 5))
            with self.subTest(changes=changes), self.assertRaisesRegex(runner.MatrixUnavailable, "reference_changed"):
                envelope.accepts(current)

    def test_missing_windows_and_reserve_loss_are_not_zero(self):
        with self.assertRaisesRegex(runner.MatrixUnavailable, "ten_reference"):
            runner.BaselineEnvelope(self.points(0, 9))
        reference = list(self.points(0, 10))
        reference[4] = replace(reference[4], physical_available_bytes=(4 << 30) - 1)
        with self.assertRaisesRegex(runner.MatrixUnavailable, "reserve_unavailable"):
            runner.BaselineEnvelope(tuple(reference))


class MemoryPath:
    def __init__(self, value="memory"):
        self.value = value
    def __truediv__(self, name):
        return MemoryPath(self.value + "/" + str(name))
    def mkdir(self):
        pass
    def open(self, *args, **kwargs):
        return io.StringIO()


@dataclass(frozen=True)
class FabricatedTrace:
    run_id: str
    conditions: object


class FabricatedEpisode:
    def __init__(self, owner, spec):
        self.owner, self.spec, self.run_id = owner, spec, spec.run_id
        self.cleanup_complete = False
        self.started = False
    def verify_baseline(self):
        self.owner.events.append((self.run_id, "baseline"))
        if self.owner.failure == "baseline":
            raise runner.MatrixUnavailable("fixture_baseline_unavailable")
    def start(self):
        if self.started:
            raise AssertionError("double launch")
        self.started = True
        self.owner.events.append((self.run_id, "start"))
    def observe(self):
        self.owner.events.append((self.run_id, "observe"))
        if self.owner.failure == "observe":
            raise runner.MatrixUnavailable("fixture_observation_failed")
    def restore_and_drain(self):
        self.owner.events.append((self.run_id, "cleanup"))
        if not self.owner.cleanup_pending:
            self.cleanup_complete = True
            self.owner.active = None
    def finish_trace(self):
        if not self.cleanup_complete:
            raise AssertionError("measurement before cleanup")
        self.owner.events.append((self.run_id, "trace"))
        return runner.NativeEpisodeObservation(FabricatedTrace(self.run_id,
                replace(conditions(), task_count=self.spec.scenario.task_count)), object())


class FabricatedPass:
    def __init__(self, failure=None, cleanup_pending=False):
        self.events, self.episodes = [], []
        self.active = None
        self.failure, self.cleanup_pending = failure, cleanup_pending
        self.closed = False
    @property
    def pending_custody(self):
        return self.active is not None
    def assert_unchanged(self):
        if self.closed:
            raise AssertionError("closed owner queried")
    def open_episode(self, *, spec, directory):
        if self.active is not None:
            raise AssertionError("overlapping original owners")
        self.active = FabricatedEpisode(self, spec)
        self.episodes.append(self.active)
        return self.active
    def recover_once(self):
        self.events.append((None, "recover"))
    def close(self):
        if self.pending_custody:
            raise AssertionError("live custody discarded")
        self.closed = True


class OrchestratorTests(unittest.TestCase):
    def orchestrator(self, owner):
        journal = Mock(directory=MemoryPath())
        return runner.MatrixOrchestrator(owner=owner, journal=journal, registration=registration())

    def test_launch_follows_intent_and_verified_baseline_once(self):
        owner = FabricatedPass(failure="observe")
        coordinator = self.orchestrator(owner)
        with patch.object(runner, "write_new", return_value="a" * 64), self.assertRaisesRegex(
                runner.MatrixUnavailable, "fixture_observation_failed"):
            coordinator.run()
        self.assertEqual(len(owner.episodes), 1)
        self.assertEqual([event for _, event in owner.events][:4], ["baseline", "start", "observe", "cleanup"])
        self.assertTrue(owner.closed)
        phases = [call.args[0] for call in coordinator.journal.event.call_args_list]
        self.assertLess(phases.index("episode_intent"), phases.index("launch_attempted"))

    def test_baseline_failure_launches_nothing_and_still_cleans_original_owner(self):
        owner = FabricatedPass(failure="baseline")
        coordinator = self.orchestrator(owner)
        with patch.object(runner, "write_new", return_value="a" * 64), self.assertRaisesRegex(
                runner.MatrixUnavailable, "fixture_baseline_unavailable"):
            coordinator.run()
        self.assertEqual(len(owner.episodes), 1)
        self.assertNotIn("start", [event for _, event in owner.events])
        self.assertTrue(owner.closed)

    def test_pending_cleanup_retains_same_episode_and_never_starts_the_next(self):
        owner = FabricatedPass(failure="observe", cleanup_pending=True)
        coordinator = self.orchestrator(owner)
        with patch.object(runner, "write_new", return_value="a" * 64), self.assertRaises(runner.MatrixUnsettled) as caught:
            coordinator.run()
        held = caught.exception
        self.assertIs(held.owner, owner)
        self.assertIs(held.episode, owner.episodes[0])
        self.assertEqual(len(owner.episodes), 1)
        self.assertFalse(held.recover_once())
        owner.cleanup_pending = False
        self.assertTrue(held.recover_once())
        self.assertEqual(sum(event == "start" for _, event in owner.events), 1)

    def test_recovery_requires_episode_proof_even_when_pass_claims_empty(self):
        owner = SimpleNamespace(pending_custody=False, recover_once=Mock(), close=Mock())
        episode = SimpleNamespace(cleanup_complete=False, restore_and_drain=Mock())
        held = runner.MatrixUnsettled(owner, episode)
        self.assertFalse(held.recover_once())
        owner.close.assert_not_called()
        episode.cleanup_complete = True
        owner.pending_custody = None
        self.assertFalse(held.recover_once())
        owner.close.assert_not_called()

    def test_recovery_also_requires_original_coverage_to_settle(self):
        owner = SimpleNamespace(pending_custody=False, recover_once=Mock(), close=Mock())
        coverage = SimpleNamespace(pending_custody=True)
        held = runner.MatrixUnsettled(owner, retained_coverage=coverage)
        self.assertFalse(held.recover_once())
        owner.close.assert_called_once_with()
        self.assertFalse(held.recover_once())
        owner.close.assert_called_once_with()
        coverage.pending_custody = False
        self.assertTrue(held.recover_once())
        owner.close.assert_called_once_with()

    def test_failed_pass_is_not_replayed_with_same_custody(self):
        owner = FabricatedPass(failure="baseline")
        coordinator = self.orchestrator(owner)
        with patch.object(runner, "write_new", return_value="a" * 64), self.assertRaises(runner.MatrixUnavailable):
            coordinator.run()
        with self.assertRaisesRegex(runner.MatrixUnavailable, "pass_replay_forbidden"):
            coordinator.run()

    def test_result_not_published_before_daily_coverage_settles(self):
        owner = FabricatedPass()
        coordinator = self.orchestrator(owner)
        coordinator.retained_coverage = SimpleNamespace(pending_custody=True)
        coordinator._noise = Mock(return_value={(comparison, scenario.name): None
            for scenario in runner.SCENARIOS for comparison in Comparison})
        with patch.object(runner, "required_episodes", return_value=()), \
                patch.object(runner, "analyze_comparison"), \
                patch.object(runner, "write_new", return_value="a" * 64) as writer, \
                self.assertRaises(runner.MatrixUnsettled) as caught:
            coordinator.run()
        self.assertIs(caught.exception.retained_coverage, coordinator.retained_coverage)
        self.assertTrue(caught.exception.owner_closed)
        self.assertFalse(any(call.args[0].value.endswith("result.json") for call in writer.call_args_list))

    def test_complete_in_memory_matrix_still_cannot_promote(self):
        owner = FabricatedPass()
        coordinator = self.orchestrator(owner)
        lookup = {item.run_id: item for item in runner.required_episodes(coordinator.registration)}
        def fabricated_record(trace, *, schedule, slot, variant, provenance):
            item = lookup[trace.run_id]
            p95 = 80 if variant is Variant.B and item.scenario.scenario_class is runner.ScenarioClass.CPU_CONTENTION else 100
            output = record(variant, item.pair_index, foreground_p95=p95, makespan=100, units=100,
                scenario=item.scenario.name, scenario_class=item.scenario.scenario_class,
                conditions_override=trace.conditions, comparison=item.comparison)
            return replace(output, run_id=trace.run_id)
        with patch.object(runner, "write_new", return_value="a" * 64), \
                patch("tests.benchmarks.adaptive_measurements.reduce_metrics", return_value=metrics()), \
                patch("tests.benchmarks.adaptive_measurements.reduce_run", side_effect=fabricated_record), \
                patch("tests.benchmarks.adaptive_measurements.verify_native_provenance"):
            result = coordinator.run()
        self.assertEqual(result["completed_episodes"], 840)
        self.assertEqual(result["comparison_records"], 420)
        self.assertEqual(result["verdict"], "NO_THRESHOLD_DEFINED")
        self.assertFalse(result["promotion_permitted"])
        self.assertTrue(owner.closed)
        self.assertEqual(len(owner.episodes), 840)
        self.assertTrue(all(episode.cleanup_complete for episode in owner.episodes))


class NativeEntryCustodyTests(unittest.TestCase):
    def invoke(self, coverage, *, write_error=None, acquisition_error=None):
        value = registration()
        with patch.object(runner, "os", SimpleNamespace(name="nt")), \
                patch("tests.windows.adaptive_capability_runner.base_python"), \
                patch.object(runner, "MatrixJournal", return_value=Mock(directory=MemoryPath())), \
                patch("tests.windows.adaptive_admission.require_continuous_admission",
                      return_value=coverage, side_effect=acquisition_error), \
                patch.object(runner, "write_new", side_effect=write_error):
            return runner.run_native_matrix(value, "unused")

    def test_missing_bridge_logging_failure_preserves_original_coverage(self):
        for error in (OSError("fixture disk failure"), KeyboardInterrupt()):
            coverage = SimpleNamespace(pending_custody=True)
            with self.subTest(error=type(error).__name__), self.assertRaises(runner.MatrixUnsettled) as caught:
                self.invoke(coverage, write_error=error)
            self.assertIs(caught.exception.owner, coverage)

    def test_invalid_primitive_return_never_replaces_original_coverage(self):
        for invalid in (None, True, {}, []):
            coverage = SimpleNamespace(pending_custody=True, open_p6_pass=lambda **kwargs: invalid)
            with self.subTest(invalid=invalid), self.assertRaises(runner.MatrixUnsettled) as caught:
                self.invoke(coverage)
            self.assertIs(caught.exception.owner, coverage)

    def test_invalid_object_remains_retained_without_a_guessed_recovery_api(self):
        unknown = object()
        coverage = SimpleNamespace(pending_custody=False, open_p6_pass=lambda **kwargs: unknown,
                                   recover_once=Mock(), close=Mock())
        with self.assertRaises(runner.MatrixUnsettled) as caught:
            self.invoke(coverage)
        self.assertIs(caught.exception.owner, coverage)
        self.assertIs(caught.exception.unverified_custody, unknown)
        self.assertFalse(caught.exception.recover_once())
        coverage.close.assert_not_called()

    def test_acquisition_exception_with_original_owner_survives_failed_logging(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        coverage = SimpleNamespace(pending_custody=True)
        primary = NativeRunUnsettled(coverage)
        with self.assertRaises(runner.MatrixUnsettled) as caught:
            self.invoke(None, acquisition_error=primary, write_error=OSError("fixture disk failure"))
        self.assertIs(caught.exception.owner, coverage)
        self.assertIs(caught.exception.primary, primary)

    def test_acquisition_additional_custody_blocks_false_settlement(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        coverage = SimpleNamespace(pending_custody=False, recover_once=Mock(), close=Mock())
        unknown = object()
        primary = NativeRunUnsettled(coverage, additional_custody=unknown)
        with self.assertRaises(runner.MatrixUnsettled) as caught:
            self.invoke(None, acquisition_error=primary)
        self.assertIs(caught.exception.unverified_custody, unknown)
        self.assertFalse(caught.exception.recover_once())
        coverage.close.assert_not_called()

    def test_constructor_failure_closes_original_pass_fence_once(self):
        owner = FabricatedPass()
        owner.close = Mock(wraps=owner.close)
        coverage = SimpleNamespace(pending_custody=False, open_p6_pass=lambda **kwargs: owner)
        with patch.object(runner, "MatrixOrchestrator", side_effect=ValueError("fixture constructor failure")), \
                self.assertRaisesRegex(ValueError, "fixture constructor failure"):
            self.invoke(coverage)
        owner.close.assert_called_once_with()
        self.assertTrue(owner.closed)

    def test_constructor_failure_with_unsettled_close_retains_original_pass(self):
        owner = FabricatedPass()
        owner.close = Mock(side_effect=OSError("fixture close failure"))
        coverage = SimpleNamespace(pending_custody=False, open_p6_pass=lambda **kwargs: owner)
        with patch.object(runner, "MatrixOrchestrator", side_effect=ValueError("fixture constructor failure")), \
                self.assertRaises(runner.MatrixUnsettled) as caught:
            self.invoke(coverage)
        self.assertIs(caught.exception.owner, owner)
        self.assertIsInstance(caught.exception.primary, ValueError)
        owner.close.assert_called_once_with()

    def test_constructor_failure_retains_pending_pass_and_original_coverage(self):
        owner = SimpleNamespace(pending_custody=True, assert_unchanged=Mock(),
            open_episode=Mock(), recover_once=Mock(), close=Mock())
        coverage = SimpleNamespace(pending_custody=True, open_p6_pass=lambda **kwargs: owner)
        with patch.object(runner, "MatrixOrchestrator", side_effect=ValueError("fixture constructor failure")), \
                self.assertRaises(runner.MatrixUnsettled) as caught:
            self.invoke(coverage)
        held = caught.exception
        self.assertIs(held.owner, owner)
        self.assertIs(held.retained_coverage, coverage)
        owner.pending_custody = False
        self.assertFalse(held.recover_once())
        coverage.pending_custody = False
        self.assertTrue(held.recover_once())


class MatrixCliCustodyTests(unittest.TestCase):
    def test_broken_console_does_not_drop_original_pending_owner(self):
        from tests.benchmarks import adaptive_runner as cli
        pending = runner.MatrixUnsettled(object())
        pending.recover_once = Mock(return_value=True)
        with patch.object(cli, "_read_json", return_value={}), \
                patch.object(runner, "parse_registration", return_value=registration()), \
                patch.object(runner, "run_native_matrix", side_effect=pending), \
                patch("builtins.print", side_effect=BrokenPipeError("fixture lost console")):
            result = cli.main(["run-matrix", "--registration", "unused.json", "--evidence-dir", "unused"])
        self.assertEqual(result, 3)
        pending.recover_once.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
