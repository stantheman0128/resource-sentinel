"""V2 publication bookkeeping with explicit synthetic source/native seams.

Run/artifact/bundle files, type and original-object guards, provider retention,
and the S1 reducer are real. Bootstrap attestation, native host observations,
build-reader results and measurements are synthetic. The one positive envelope
test explicitly substitutes completed-case verification; it does not fabricate
NativeScopeCompletion or prove thirteen native cleanups. Actual checked-byte
imports and original scope/release integration have separate test modules.
"""
from copy import copy, deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import capability_build as builds
from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive.decision import Mode, validate_policy_profile
from tests.test_adaptive_capability_evidence import LOGON, s1_data
from tests.windows import adaptive_capability_runner as runner
from tests.windows import adaptive_producer_bootstrap as bootstraps
from tests.windows import adaptive_s1_provider as providers
from tests.windows import adaptive_s1_measurements as measurements


class S1PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="sentinel-s1-publication-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.directory = self.root / "output"
        self.directory.mkdir()
        producer = self.root / "producer"
        producer.mkdir()
        self.profile = replace(validate_policy_profile(json.loads(
            (Path(__file__).resolve().parents[1] / "config/adaptive.example.json").read_text("utf-8"))),
            mode=Mode.ENFORCE)
        self.context = evidence.LiveCapabilityContext("c" * 64, 10, 0, 26100, 8, 1, "255",
            LOGON, 1, 0, "3.13.0", 64, "d" * 64, False, "e" * 64)
        self.build = evidence.BuildIdentity("a" * 64, "b" * 64)
        # Exact data type and safe real directories; only the canonical locator
        # is synthetic here. No SourceBoundBuildSource inventory proof is claimed.
        with patch.object(builds, "daily_locations", return_value=(evidence._ROOT, self.root)):
            self.binding = builds.SourceBinding(1, "canonical_runtime_fixture_inventory",
                str(evidence._ROOT.resolve()), str(producer), "f" * 64)
        self.reader = builds.SourceBoundBuildSource.__new__(builds.SourceBoundBuildSource)
        self.reader.binding = self.binding
        self.bootstrap = bootstraps.ProducerBootstrap.__new__(bootstraps.ProducerBootstrap)
        self.bootstrap.source_binding = self.binding
        self.bootstrap.build_source = self.reader
        self.bootstrap.runtime_root = Path(self.binding.runtime_root)
        self.bootstrap.producer_root = producer
        self.bootstrap_attestation = self.install(patch.object(bootstraps.ProducerBootstrap,
            "assert_unchanged", autospec=True, return_value=self.build))
        self.reader_observation = self.install(patch.object(builds.SourceBoundBuildSource,
            "__call__", autospec=True, return_value=self.build))
        self.context_observation = self.install(patch.object(evidence.NativeContextSource,
            "__call__", autospec=True, return_value=self.context))
        self.install(patch.object(runner, "base_python", return_value=Path(sys.executable)))
        self.original_provider_ids = set(providers._PROVIDERS)
        self.addCleanup(self.remove_fixture_providers)

    def install(self, override):
        value = override.start()
        self.addCleanup(override.stop)
        return value

    def remove_fixture_providers(self):
        for key in set(providers._PROVIDERS) - self.original_provider_ids:
            providers._PROVIDERS.pop(key)

    def new_run(self, *, bootstrap=None):
        return runner.NativeEvidenceRun(self.directory, self.profile,
            bootstrap=self.bootstrap if bootstrap is None else bootstrap)

    def assert_no_publication(self):
        self.assertFalse((self.directory / "S1.json").exists())
        self.assertFalse((self.directory / "bundle.json").exists())

    def original_provider(self, run):
        directory = self.directory / "provider"
        directory.mkdir()
        owner = providers.S1SerialProvider(directory, self.context, bootstrap=self.bootstrap)
        run._s1_provider = owner
        return owner

    def unentered_case(self, owner, kind="round"):
        # Actual source-only constructor. No demand, native scope, completion
        # or release is fabricated; this is an explicitly unentered case.
        case = providers.S1Case(owner, kind, _token=providers._NEW)
        owner._cases.append(case)
        owner._current = case
        return case

    def test_v2_run_pins_exact_bootstrap_binding_reader_and_closed_record(self):
        run = self.new_run()
        record = json.loads((self.directory / "run.json").read_text("utf-8"))
        self.assertEqual(set(record), {"schema_version", "run_id", "context", "build",
            "profile_revision", "source_binding"})
        self.assertIs(type(record["schema_version"]), int)
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(record["source_binding"], self.binding.to_dict())
        self.assertEqual(record["context"], asdict(self.context))
        self.assertEqual(record["build"], asdict(self.build))
        self.assertIs(run._bootstrap, self.bootstrap)
        self.assertIs(run.source_binding, self.binding)
        self.assertIs(run.build_source, self.reader)
        self.assertTrue(self.bootstrap_attestation.called)
        self.assert_no_publication()

    def test_nonoriginal_bootstrap_type_is_refused_before_native_context(self):
        self.context_observation.reset_mock()
        with self.assertRaises(runner.NativeRunBlocked):
            self.new_run(bootstrap=object())
        self.context_observation.assert_not_called()
        self.assertFalse((self.directory / "run.json").exists())

    def test_bootstrap_attestation_failure_precedes_native_context_and_run_file(self):
        failure = bootstraps.ProducerBootstrapError("synthetic changed source")
        self.bootstrap_attestation.side_effect = failure
        with self.assertRaises(bootstraps.ProducerBootstrapError) as caught:
            self.new_run()
        self.assertIs(caught.exception, failure)
        self.context_observation.assert_not_called()
        self.assertFalse((self.directory / "run.json").exists())

    def test_equal_callback_cannot_replace_original_build_reader(self):
        run = self.new_run()
        calls = []
        run.build_source = lambda: calls.append(True) or self.build
        with self.assertRaises(runner.NativeRunBlocked):
            run.assert_unchanged()
        self.assertEqual(calls, [])
        self.assert_no_publication()

    def test_equal_copy_of_reader_or_binding_cannot_replace_original(self):
        run = self.new_run()
        for name, replacement in (("build_source", copy(self.reader)), ("source_binding", copy(self.binding)),
                ("_bootstrap", copy(self.bootstrap))):
            original = getattr(run, name)
            with self.subTest(name=name), patch.object(run, name, replacement):
                with self.assertRaises(runner.NativeRunBlocked):
                    run.assert_unchanged()
            self.assertIs(getattr(run, name), original)
        self.assert_no_publication()

    def test_removing_bootstrap_cannot_downgrade_an_existing_v2_run(self):
        run = self.new_run()
        run._bootstrap = None
        with self.assertRaises(runner.NativeRunBlocked):
            run.publish_gate("S1", s1_data())
        self.assert_no_publication()

    def test_changed_context_and_profile_refuse_before_publication(self):
        run = self.new_run()
        self.context_observation.return_value = replace(self.context, python_version="3.13.1")
        with self.assertRaises(runner.NativeRunBlocked):
            run.assert_unchanged()
        self.context_observation.return_value = self.context
        run.profile = replace(self.profile, mode=Mode.OFF)
        with self.assertRaises(runner.NativeRunBlocked):
            run.assert_unchanged()
        self.assert_no_publication()

    def test_existing_run_cannot_drop_v2_binding_or_add_unreviewed_fields(self):
        self.new_run()
        path = self.directory / "run.json"
        original = json.loads(path.read_text("utf-8"))
        cases = [dict(original, schema_version=1), dict(original, schema_version=True),
                 dict(original, unrelated=True),
                 {key: value for key, value in original.items() if key != "source_binding"}]
        for changed in cases:
            with self.subTest(keys=sorted(changed)):
                path.write_bytes(runner.canonical(changed))
                with self.assertRaises(runner.NativeRunBlocked):
                    self.new_run()
        self.assert_no_publication()

    def test_arbitrary_s1_data_and_unintegrated_v2_gates_cannot_publish(self):
        run = self.new_run()
        for gate in ("S1", "S2", "S3", "P4", "P5", "P6"):
            with self.subTest(gate=gate), self.assertRaises(runner.NativeRunBlocked):
                run.publish_gate(gate, s1_data() if gate == "S1" else {})
        self.assert_no_publication()

    def test_existing_v2_run_record_mutation_is_refused_from_disk(self):
        run = self.new_run()
        changed = dict(run.record, schema_version=1)
        run.run_path.write_bytes(runner.canonical(changed))
        with self.assertRaisesRegex(runner.NativeRunBlocked, "run_record_changed"):
            run.assert_unchanged()
        self.assert_no_publication()

    def test_replaced_output_directory_is_not_adopted(self):
        run = self.new_run()
        moved = self.root / "original-output"
        self.directory.rename(moved)
        self.directory.mkdir()
        (self.directory / "run.json").write_bytes((moved / "run.json").read_bytes())
        with self.assertRaisesRegex(runner.NativeRunBlocked, "run_directory_changed"):
            run.assert_unchanged()
        self.assert_no_publication()

    def test_equal_context_callback_cannot_replace_original_reader(self):
        run = self.new_run()
        calls = []
        run.context_source = lambda: calls.append(True) or self.context
        with self.assertRaisesRegex(runner.NativeRunBlocked, "original_bootstrap_required"):
            run.assert_unchanged()
        self.assertEqual(calls, [])

    def test_provider_is_retained_before_constructor_and_failure_cannot_retry(self):
        run = self.new_run()
        failure = RuntimeError("synthetic constructor interruption")
        seen = []

        def interrupted(owner, directory, context, *, bootstrap=None):
            self.assertIs(type(owner), providers.S1SerialProvider)
            self.assertIs(run._s1_provider, owner)
            self.assertIs(context, run.context)
            self.assertIs(bootstrap, self.bootstrap)
            self.assertFalse(run._s1_initialized)
            seen.append(owner)
            raise failure

        with patch.object(providers.S1SerialProvider, "__init__", autospec=True,
                side_effect=interrupted) as construct, patch.object(measurements, "produce_s1") as produce:
            with self.assertRaises(RuntimeError) as caught:
                run.run_s1()
            self.assertIs(caught.exception, failure)
            with self.assertRaisesRegex(runner.NativeRunBlocked, "already_started"):
                run.run_s1()
        self.assertEqual(construct.call_count, 1)
        produce.assert_not_called()
        self.assertIs(run._s1_provider, seen[0])
        self.assertTrue(run._s1_started)
        self.assertFalse(run._s1_initialized)
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_measurement_failure_retains_exact_pending_case_and_original_provider(self):
        run = self.new_run()
        failure = OSError("synthetic measurement failure")
        seen = []

        def measure(owner, directory, context):
            self.assertIs(owner, run._s1_provider)
            self.assertTrue(run._s1_initialized)
            self.assertIs(owner._bootstrap, self.bootstrap)
            self.assertIs(context, self.context)
            self.assertEqual(owner.directory, directory)
            seen.append(self.unentered_case(owner))
            raise failure

        with patch.object(measurements, "produce_s1", side_effect=measure) as produce:
            with self.assertRaises(runner.NativeRunUnsettled) as caught:
                run.run_s1()
            with self.assertRaisesRegex(runner.NativeRunBlocked, "already_started"):
                run.run_s1()
        self.assertEqual(produce.call_count, 1)
        self.assertIs(caught.exception.coverage, run._s1_provider)
        self.assertIs(caught.exception.additional_custody, failure)
        self.assertIs(caught.exception.__cause__, failure)
        self.assertIs(run._s1_provider.current_case, seen[0])
        self.assertFalse(seen[0]._closed)
        self.assertIsNone(run._s1_publication)
        failure_record = json.loads((run._s1_provider.directory / "failure.json").read_text("utf-8"))
        self.assertEqual(failure_record["status"], "failed")
        self.assertFalse(failure_record["promotion"])
        self.assert_no_publication()

    def test_failure_log_error_cannot_lose_original_pending_custody(self):
        run = self.new_run()
        failure = KeyboardInterrupt("synthetic interrupted measurement")

        def measure(owner, directory, context):
            self.unentered_case(owner)
            raise failure

        with patch.object(measurements, "produce_s1", side_effect=measure), \
                patch.object(runner, "_write_new", side_effect=OSError("synthetic full output disk")):
            with self.assertRaises(runner.NativeRunUnsettled) as caught:
                run.run_s1()
        self.assertIs(caught.exception.coverage, run._s1_provider)
        self.assertIs(caught.exception.additional_custody, failure)
        self.assertIn("native_failure_evidence_write_failed", failure.__notes__)
        self.assertEqual(len(run._s1_provider._cases), 1)
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_returned_data_with_pending_custody_cannot_publish(self):
        run = self.new_run()

        def measure(owner, directory, context):
            self.unentered_case(owner)
            return s1_data()

        with patch.object(measurements, "produce_s1", side_effect=measure):
            with self.assertRaises(runner.NativeRunUnsettled) as caught:
                run.run_s1()
        self.assertIs(caught.exception.coverage, run._s1_provider)
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_returned_data_without_thirteen_original_cases_is_refused(self):
        run = self.new_run()
        with patch.object(measurements, "produce_s1", return_value=s1_data()):
            with self.assertRaisesRegex(runner.NativeRunBlocked, "cases_incomplete"):
                run.run_s1()
        self.assertEqual(run._s1_provider.completed_cases, ())
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_completion_guard_rejects_foreign_original_provider(self):
        run = self.new_run()
        owner = self.original_provider(run)
        other_dir = self.directory / "other-provider"
        other_dir.mkdir()
        other = providers.S1SerialProvider(other_dir, self.context, bootstrap=self.bootstrap)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "original_provider_required"):
            run._verify_s1_completion(other)
        self.assertIs(run._s1_provider, owner)

    def test_completion_guard_rejects_wrong_order_and_unearned_closed_flags(self):
        run = self.new_run()
        owner = self.original_provider(run)
        expected = ("self_stop", "empty_probe", "foreign_parent", *("round",) * 10)
        for kind in expected:
            case = self.unentered_case(owner, kind)
            # Deliberately invalid negative fixture: a local bool never proves
            # original NativeScopeCompletion or positive daily release.
            case._closed = True
        owner._cases[0], owner._cases[1] = owner._cases[1], owner._cases[0]
        with self.assertRaisesRegex(runner.NativeRunBlocked, "cases_incomplete"):
            run._verify_s1_completion(owner)
        owner._cases[0], owner._cases[1] = owner._cases[1], owner._cases[0]
        with self.assertRaisesRegex(runner.NativeRunBlocked, "cleanup_unverified"):
            run._verify_s1_completion(owner)
        self.assert_no_publication()

    def test_bookkeeping_only_run_s1_writes_bound_envelopes_from_same_result(self):
        run = self.new_run()
        data = s1_data()
        # Only envelope bookkeeping is asserted positively here. Original
        # completion/release is deliberately NOT simulated as native evidence.
        with patch.object(measurements, "produce_s1", return_value=data) as produce, \
                patch.object(run, "_verify_s1_completion") as completion:
            result = run.run_s1()
        owner = run._s1_provider
        self.assertIs(type(owner), providers.S1SerialProvider)
        produce.assert_called_once_with(owner, owner.directory, self.context)
        self.assertEqual(completion.call_count, 2)
        for call in completion.call_args_list:
            self.assertIs(call.args[0], owner)
        self.assertIs(run._s1_publication[0], owner)
        self.assertIs(run._s1_publication[1], data)
        self.assertEqual(run._s1_publication[2], runner.canonical(data))
        raw = (self.directory / "S1.json").read_bytes()
        artifact = json.loads(raw)
        self.assertEqual(set(artifact), {"schema_version", "run_id", "gate", "evidence_source", "data"})
        self.assertEqual(artifact, dict(schema_version=1, run_id=run.record["run_id"], gate="S1",
            evidence_source="native", data=data))
        bundle_bytes = (self.directory / "bundle.json").read_bytes()
        bundle = json.loads(bundle_bytes)
        self.assertEqual(set(bundle), {"schema_version", "kind", "run_id", "evidence_source",
            "build", "context", "profile_revision", "artifacts", "source_binding"})
        self.assertEqual(bundle["schema_version"], 2)
        self.assertEqual(bundle["source_binding"], self.binding.to_dict())
        self.assertEqual(bundle["context"], asdict(self.context))
        self.assertEqual(bundle["build"], asdict(self.build))
        self.assertEqual(bundle["artifacts"], [dict(gate="S1", path="S1.json",
            sha256=hashlib.sha256(raw).hexdigest())])
        self.assertEqual(result["artifact_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["bundle_sha256"], hashlib.sha256(bundle_bytes).hexdigest())
        self.assertEqual(result["measured_gates"], ["S1"])
        self.assertIs(result["promotion"], False)
        with self.assertRaisesRegex(runner.NativeRunBlocked, "already_started"):
            run.run_s1()

    def test_original_result_copy_or_later_mutation_is_refused_before_write(self):
        run = self.new_run()
        data = s1_data()
        # Capture the real run_s1 handoff without publishing. The substitution
        # isolates result-object custody; real completion has negative tests.
        with patch.object(measurements, "produce_s1", return_value=data), \
                patch.object(run, "_verify_s1_completion"), patch.object(run, "publish_gate"):
            run.run_s1()
        with self.assertRaisesRegex(runner.NativeRunBlocked, "original_s1_result_required"):
            run.publish_gate("S1", deepcopy(data))
        data["rounds"][0]["rate_bp"] = 2499
        with self.assertRaisesRegex(runner.NativeRunBlocked, "original_s1_result_required"):
            run.publish_gate("S1", data)
        self.assert_no_publication()

    def test_publication_reaudits_source_after_producer_return(self):
        run = self.new_run()
        failure = bootstraps.ProducerBootstrapError("synthetic source changed after measurement")

        def measure(owner, directory, context):
            self.bootstrap_attestation.side_effect = failure
            return s1_data()

        with patch.object(measurements, "produce_s1", side_effect=measure), \
                patch.object(run, "_verify_s1_completion"):
            with self.assertRaises(bootstraps.ProducerBootstrapError) as caught:
                run.run_s1()
        self.assertIs(caught.exception, failure)
        self.assertIsNone(run._s1_publication)
        self.assertIs(type(run._s1_provider), providers.S1SerialProvider)
        self.assert_no_publication()

    def test_other_gate_artifact_cannot_be_mixed_into_v2_s1_bundle(self):
        run = self.new_run()
        (self.directory / "S2.json").write_text("{}", encoding="utf-8")
        with patch.object(measurements, "produce_s1", return_value=s1_data()), \
                patch.object(run, "_verify_s1_completion"):
            with self.assertRaisesRegex(runner.NativeRunBlocked, "gate_requires_own_producer"):
                run.run_s1()
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_synthetic_measurement_still_must_pass_the_real_s1_reducer(self):
        run = self.new_run()
        data = s1_data()
        data["rounds"][0]["rate_bp"] = 2499
        with patch.object(measurements, "produce_s1", return_value=data), \
                patch.object(run, "_verify_s1_completion"):
            with self.assertRaises(evidence.CapabilityEvidenceError):
                run.run_s1()
        self.assertIsNone(run._s1_publication)
        self.assert_no_publication()

    def test_provider_attestation_failure_precedes_case_capture(self):
        run = self.new_run()
        owner = self.original_provider(run)
        failure = bootstraps.ProducerBootstrapError("synthetic changed fixture")
        self.bootstrap_attestation.side_effect = failure
        with patch.object(providers, "_capture_generation") as capture:
            with self.assertRaises(bootstraps.ProducerBootstrapError) as caught:
                owner.start_case()
        self.assertIs(caught.exception, failure)
        capture.assert_not_called()
        self.assertEqual(owner._cases, [])
        self.assertIsNone(owner.current_case)

    def test_generation_binding_refusal_keeps_original_case_and_cleanup_needs_no_audit(self):
        run = self.new_run()
        owner = self.original_provider(run)
        row = dict(source_root=str(self.bootstrap.runtime_root), source_digest="0" * 64)
        with patch.object(providers, "_capture_generation", return_value=providers._canonical(row)), \
                patch.object(providers.DailyExperimentDemand, "capture") as demand_capture:
            with self.assertRaisesRegex(providers.S1ProviderError, "bootstrap_generation_changed"):
                owner.start_case()
        demand_capture.assert_not_called()
        case = owner.current_case
        self.assertIs(type(case), providers.S1Case)
        self.assertIsNone(case.demand)
        self.assertFalse(case._capture_entered)
        self.bootstrap_attestation.reset_mock()
        self.bootstrap_attestation.side_effect = AssertionError("cleanup must not re-audit source")
        result = owner.recover_once()
        self.assertEqual(result["state"], "NO_DEMAND_CAPTURED")
        self.assertIs(result["demand_captured"], False)
        self.assertIs(result["launch_authorized"], False)
        self.assertIs(case._closed, True)
        self.assertTrue(case.errors)
        self.bootstrap_attestation.assert_not_called()
        self.assert_no_publication()


if __name__ == "__main__":
    unittest.main()
