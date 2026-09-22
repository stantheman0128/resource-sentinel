"""External-console P6 raw measurement producer, with no promotion side effect.

The pure A/B analyzer is deliberately separate. This module collects real raw
measurements and records every missing qualification; it cannot invent a
RunRecord from missing native lifecycle, cap-write audit or process coverage.
The real daily continuous-admission provider is required before any fixture or
probe starts. An isolated data directory is never an admission authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import argparse
import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
from uuid import uuid4

from tests.benchmarks.adaptive_ab import (
    CacheState, Comparison, DEFAULT_SCENARIOS, EvidenceSource, FixedConditions,
    MIN_PAIRS_PER_SCENARIO, NoiseEvidence, Variant, analyze_comparison,
    build_schedule, overall_verdict, parse_run_record, render_report,
)
from tests.fixtures.adaptive_workload import SCENARIOS, dataset_sha256


ROOT = Path(__file__).resolve().parents[2]
BASE_PYTHON = Path(r"C:\Python313\python.exe")
DAILY_REPO = Path(r"C:\Users\stans\Projects\resource-sentinel")
MAX_RAW_BYTES = 16 << 20
MAX_SAMPLE_COUNT = 200
PHYSICAL_RESERVE_BYTES = COMMIT_RESERVE_BYTES = 4 << 30


class MeasurementBlocked(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class PendingAdmissionCleanup(MeasurementBlocked):
    """Keep the original authority alive across a failed finish attempt."""
    def __init__(self, scope, directory, artifact, reason):
        self.scope, self.directory, self.artifact = scope, directory, artifact
        super().__init__(reason)

    def retry(self):
        self.scope.finish()
        self.artifact["admission_cleanup_settled"] = True
        _write_new(self.directory / "cleanup-settled.json", {
            "schema_version": 1, "admission_cleanup_settled": True,
            "ab_record_produced": False, "promotion_permitted": False})
        return self.artifact


def _digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _write_new(path, payload):
    encoded = json.dumps(payload, sort_keys=True, allow_nan=False, ensure_ascii=False).encode("utf-8")
    if len(encoded) > MAX_RAW_BYTES:
        raise MeasurementBlocked("ab_evidence_size_exceeded")
    with Path(path).open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())


def _read_json(path, maximum=2 << 20):
    with Path(path).open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise MeasurementBlocked("ab_evidence_size_exceeded")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MeasurementBlocked("ab_duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(value):
        raise MeasurementBlocked("ab_nonfinite_json_number")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def load_schedule(path):
    raw = _read_json(path)
    keys = {"schema_version", "seed", "pairs_per_scenario", "slots", "measured", "promotion_permitted"}
    if type(raw) is not dict or set(raw) != keys or raw["schema_version"] != 2 or \
            raw["measured"] is not False or raw["promotion_permitted"] is not False:
        raise MeasurementBlocked("ab_schedule_schema_invalid")
    schedule = build_schedule(DEFAULT_SCENARIOS, raw["seed"], raw["pairs_per_scenario"])
    expected = json.loads(json.dumps([asdict(slot) for slot in schedule.slots]))
    if raw["slots"] != expected:
        raise MeasurementBlocked("ab_schedule_seed_or_inventory_mismatch")
    return schedule


def _load_noise(path):
    if path is None:
        return {}
    raw = _read_json(path, MAX_RAW_BYTES)
    if type(raw) is not list or len(raw) > 21:
        raise MeasurementBlocked("ab_noise_inventory_invalid")
    values = {}
    keys = set(NoiseEvidence.__dataclass_fields__)
    condition_keys = set(FixedConditions.__dataclass_fields__)
    for item in raw:
        if type(item) is not dict or set(item) != keys:
            raise MeasurementBlocked("ab_noise_schema_invalid")
        item = dict(item)
        conditions = item["conditions"]
        if type(conditions) is not dict or set(conditions) != condition_keys:
            raise MeasurementBlocked("ab_noise_conditions_invalid")
        conditions = dict(conditions)
        conditions["cache_state"] = CacheState(conditions["cache_state"])
        conditions["build_variant_sha256"] = tuple((Variant(variant), digest)
                                                   for variant, digest in conditions["build_variant_sha256"])
        item["conditions"] = FixedConditions(**conditions)
        item["comparison"], item["variant"] = Comparison(item["comparison"]), Variant(item["variant"])
        item["evidence_source"] = EvidenceSource(item["evidence_source"])
        for name in ("foreground_p95_pairs_ms", "makespan_pairs_s", "repeat_run_ids"):
            if type(item[name]) is not list or len(item[name]) > 10000:
                raise MeasurementBlocked("ab_noise_observation_bound_invalid")
            item[name] = tuple(tuple(pair) for pair in item[name])
        noise = NoiseEvidence(**item)
        key = (noise.comparison, noise.scenario)
        if key in values:
            raise MeasurementBlocked("ab_noise_duplicate_inventory")
        values[key] = noise
    return values


def analyze_files(schedule_path, records_path, noise_path, output_path):
    """Read bounded evidence, require every scheduled comparison, write a report.

    Schema and arithmetic verification are not source authentication. Native
    gate verification still checks the original artifacts and their hashes.
    No result from this read-only command enables a host or changes a profile.
    """
    schedule = load_schedule(schedule_path)
    raw = _read_json(records_path, MAX_RAW_BYTES)
    if type(raw) is not list or len(raw) > 4200:
        raise MeasurementBlocked("ab_record_inventory_invalid")
    records = [parse_run_record(item) for item in raw]
    noise = _load_noise(noise_path)
    required = {(comparison, scenario) for comparison in Comparison for scenario, _ in DEFAULT_SCENARIOS}
    if any(key not in required for key in noise):
        raise MeasurementBlocked("ab_noise_scope_invalid")
    analyses = [analyze_comparison(records, comparison, scenario, kind, schedule=schedule,
                                   noise=noise.get((comparison, scenario)))
                for scenario, kind in DEFAULT_SCENARIOS for comparison in Comparison]
    report = render_report(analyses, schedule.seed)
    with Path(output_path).open("x", encoding="utf-8") as stream:
        stream.write(report)
    return {"status": "analyzed", "verdict": overall_verdict(analyses).value,
            "source_authentication": "requires_native_artifact_verifier",
            "promotion_permitted": False}


@dataclass(frozen=True)
class FixtureSpec:
    scenario: str
    tasks: int
    units: int
    memory_mib: int = 128
    seconds: int = 90

    def __post_init__(self):
        if self.scenario not in SCENARIOS:
            raise MeasurementBlocked("ab_scenario_native_fixture_unavailable")
        if type(self.tasks) is not int or not 1 <= self.tasks <= 4:
            raise MeasurementBlocked("ab_fixture_task_count_invalid")
        if type(self.units) is not int or not 1 <= self.units <= 10000:
            raise MeasurementBlocked("ab_fixture_units_invalid")
        if self.scenario == "io_bound_install" and self.units > 8:
            raise MeasurementBlocked("ab_fixture_disk_bound_invalid")
        if type(self.memory_mib) is not int or not 1 <= self.memory_mib <= 128:
            raise MeasurementBlocked("ab_fixture_memory_bound_invalid")
        if type(self.seconds) is not int or not 5 <= self.seconds <= 90:
            raise MeasurementBlocked("ab_fixture_deadline_invalid")

    @property
    def demand(self):
        # Explicit conservative command demand, not measured free capacity.
        # UI probe and measuring parent are included in the extra CPU/Commit.
        return {"cpu_units": self.tasks + 1,
                "physical_bytes": (self.tasks * (self.memory_mib + 96) + 512) << 20,
                "commit_bytes": (self.tasks * (self.memory_mib + 96) + 512) << 20,
                "io_slots": 1 if self.scenario == "io_bound_install" else 0}


def _require_platform():
    if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
        raise MeasurementBlocked("ab_windows_x64_required")
    if Path(sys.executable).resolve() != BASE_PYTHON.resolve():
        raise MeasurementBlocked("ab_base_python313_required")
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], C.c_void_p
    kernel.IsProcessInJob.argtypes = [C.c_void_p, C.c_void_p, C.POINTER(C.c_int32)]
    kernel.IsProcessInJob.restype = C.c_int32
    inside = C.c_int32()
    if not kernel.IsProcessInJob(kernel.GetCurrentProcess(), None, C.byref(inside)):
        raise MeasurementBlocked("ab_parent_job_query_failed")
    if inside.value:
        raise MeasurementBlocked("ab_external_console_required")


def _real_admission(spec):
    """No CLI/env/database alternative can replace the real host provider.

    A future deployed provider returns its retained native scope, with methods
    assert_covered(demand), acknowledge_fixture_exit(), finish(). Until that
    implementation and daily consumer handoff exist the existing prerequisite
    raises. A None/JSON receipt is not accepted as a lifetime authority.
    """
    from tests.windows.adaptive_admission import require_continuous_admission
    scope = require_continuous_admission()
    if scope is None or isinstance(scope, (dict, list, str, int, bool)):
        raise MeasurementBlocked("ab_retained_continuous_scope_unavailable")
    for name in ("assert_covered", "acknowledge_fixture_exit", "finish"):
        if not callable(getattr(scope, name, None)):
            raise MeasurementBlocked("ab_retained_continuous_scope_unavailable")
    scope.assert_covered(spec.demand)
    return scope


def fixture_command(spec, directory):
    return [str(BASE_PYTHON), str(ROOT / "tests" / "fixtures" / "adaptive_workload.py"),
            "--scenario", spec.scenario, "--directory", str(directory),
            "--tasks", str(spec.tasks), "--units", str(spec.units),
            "--memory-mib", str(spec.memory_mib), "--seconds", str(spec.seconds)]


def _power_plan():
    result = subprocess.run(["powercfg.exe", "/getactivescheme"], capture_output=True,
                            timeout=5, check=True)
    # Keep a digest of the exact bounded OS response rather than private names.
    if not result.stdout or len(result.stdout) > 4096:
        raise MeasurementBlocked("ab_power_plan_unavailable")
    return hashlib.sha256(result.stdout).hexdigest()


def _source_state():
    # Fixed tree pin covers actual source, not only a commit with dirty edits.
    paths = [ROOT / "tests" / "fixtures" / "adaptive_workload.py",
             ROOT / "tests" / "fixtures" / "win32_ui_probe.py",
             Path(__file__).resolve()]
    files = {str(path.relative_to(ROOT)).replace("\\", "/"): _digest(path) for path in paths}
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                          check=True, timeout=5, text=True).stdout.strip()
    return {"commit": head, "source_sha256": files, "python_sha256": _digest(BASE_PYTHON),
            "dataset_sha256": dataset_sha256()}


def _machine_sample(backend):
    record = backend.read()
    memory = record.memory_pages
    if memory is None or record.errors or record.processor_groups != 1:
        raise MeasurementBlocked("ab_machine_measurement_unavailable")
    physical_total, available, commit_used, commit_limit, page = memory
    return {"start_tick_100ns": record.capture_start_tick_100ns,
            "end_tick_100ns": record.capture_end_tick_100ns,
            "logical_processors": record.logical_processors,
            "cpu_times_100ns": record.cpu_times,
            "physical_used_bytes": (physical_total - available) * page,
            "physical_headroom_bytes": available * page,
            "commit_used_bytes": commit_used * page,
            "commit_headroom_bytes": (commit_limit - commit_used) * page}


def _safe_capacity(sample, demand):
    if (sample["physical_headroom_bytes"] < PHYSICAL_RESERVE_BYTES + demand["physical_bytes"] or
            sample["commit_headroom_bytes"] < COMMIT_RESERVE_BYTES + demand["commit_bytes"]):
        raise MeasurementBlocked("ab_fixture_reserve_stop")


def _wait_cooperatively(process, stop_file):
    """An observation timeout or Ctrl-C cannot discard the original child."""
    stop_file.touch(exist_ok=True)
    while process.poll() is None:
        try:
            process.wait(timeout=.25)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            continue


class WindowsFixtureObserver:
    """Collect public fixture results, actual UI delays and machine headroom.

    This observes a real A0-style direct command under an enclosing continuous
    host reservation. It does not claim the original wrapper/collector A0 or
    managed A1/B launch equivalence; the orchestrator must provide those paths
    and their audit/cost observations before a measured A/B record can exist.
    """
    def __init__(self, directory, spec):
        self.directory, self.spec = Path(directory), spec

    def measure(self, admission):
        from sentinel.adaptive.machine_sampler import _WindowsBackend
        directory, spec = self.directory, self.spec
        backend = _WindowsBackend()
        initial = _machine_sample(backend)
        _safe_capacity(initial, spec.demand)
        admission.assert_covered(spec.demand)
        ui_result, ui_ready = directory / "ui.json", directory / "ui-ready.json"
        ui_stop, work_stop = directory / "stop-ui", directory / "stop-workload"
        command = fixture_command(spec, directory)
        ui_args = [str(BASE_PYTHON), str(ROOT / "tests" / "fixtures" / "win32_ui_probe.py"),
                   "--output", str(ui_result), "--ready-file", str(ui_ready),
                   "--stop-file", str(ui_stop), "--duration-seconds", str(spec.seconds + 20),
                   "--interval-ms", "100", "--max-samples", "2000"]
        probe = workload = None
        samples, errors = [initial], []
        workload_started = workload_ended = None
        complete_exit = False
        try:
            with (directory / "probe.log").open("xb") as probe_log:
                probe = subprocess.Popen(ui_args, stdout=probe_log, stderr=probe_log)
                ready_deadline = time.monotonic() + 10
                while not ui_ready.is_file():
                    if probe.poll() is not None or time.monotonic() >= ready_deadline:
                        raise MeasurementBlocked("ab_ui_probe_not_ready")
                    time.sleep(.05)
                ready = _read_json(ui_ready)
                if ready.get("outside_job") is not True or ready.get("priority_class") != 0x20:
                    raise MeasurementBlocked("ab_ui_scope_unverified")
                admission.assert_covered(spec.demand)
                with (directory / "workload.log").open("xb") as log:
                    workload_started = time.monotonic_ns()
                    workload = subprocess.Popen(command, cwd=directory, stdout=log, stderr=log)
                    deadline = time.monotonic() + spec.seconds + 10
                    next_sample = time.monotonic() + 1
                    while workload.poll() is None:
                        now = time.monotonic()
                        if now >= deadline:
                            raise MeasurementBlocked("ab_fixture_observer_deadline")
                        if probe.poll() is not None:
                            raise MeasurementBlocked("ab_ui_probe_ended_early")
                        if now >= next_sample:
                            admission.assert_covered(spec.demand)
                            sample = _machine_sample(backend)
                            samples.append(sample)
                            if len(samples) > MAX_SAMPLE_COUNT:
                                raise MeasurementBlocked("ab_sample_bound_exceeded")
                            if (sample["physical_headroom_bytes"] < PHYSICAL_RESERVE_BYTES or
                                    sample["commit_headroom_bytes"] < COMMIT_RESERVE_BYTES):
                                raise MeasurementBlocked("ab_fixture_reserve_stop")
                            # No catch-up loop; missed windows remain visible.
                            next_sample = time.monotonic() + 1
                        time.sleep(.05)
                    workload_ended = time.monotonic_ns()
                    if workload.returncode != 0:
                        raise MeasurementBlocked("ab_fixture_nonzero_exit")
                results = [_read_json(directory / f"result-{index}.json") for index in range(spec.tasks)]
                if any(row.get("status") != "complete" or row.get("all_children_exited") is not True
                       or row.get("completed_units") != spec.units for row in results):
                    raise MeasurementBlocked("ab_fixture_completion_unverified")
                complete_exit = True
                samples.append(_machine_sample(backend))
        except BaseException as error:
            errors.append(getattr(error, "reason", type(error).__name__))
        finally:
            if workload is not None:
                _wait_cooperatively(workload, work_stop)
            if probe is not None:
                _wait_cooperatively(probe, ui_stop)
        probe_data = _read_json(ui_result) if ui_result.is_file() else None
        if probe_data is None or probe_data.get("status") != "measured":
            errors.append("ab_ui_probe_measurement_unavailable")
        results = []
        for index in range(spec.tasks):
            path = directory / f"result-{index}.json"
            if path.is_file():
                results.append(_read_json(path))
        # A successful fixture has no surviving children by its own explicit
        # wait contract. This is fixture evidence, not native managed Job-empty
        # authority. The provider must independently verify its own scope.
        if complete_exit and workload is not None and probe is not None:
            admission.acknowledge_fixture_exit()
        return {"schema_version": 1, "artifact_type": "p6_raw_fixture_observation",
                "status": "observed" if not errors else "failed", "errors": errors,
                "measurement_source": "native" if not errors else "incomplete_native",
                "fixture": asdict(spec), "workload_started_ns": workload_started,
                "workload_ended_ns": workload_ended, "machine_samples": samples,
                "ui_probe": probe_data, "fixture_results": results,
                "fixture_process_exit_confirmed": complete_exit,
                "missing_qualifications": [
                    "variant_original_wrapper_and_collector_equivalence",
                    "native_job_lifecycle_empty_and_custody_receipt",
                    "continuous_native_cap_write_audit_and_readback",
                    "all_monitor_and_wrapper_process_cost_coverage",
                    "queue_wait_and_control_state_intervals",
                    "independent_noise_repeat_pairs",
                    "between_run_cpu_and_commit_baseline_return",
                    "thermal_and_power_anomaly_observation"],
                "ab_record_produced": False, "promotion_permitted": False}


def run_raw_fixture(directory, spec):
    """Create a new isolated artifact directory and perform real measurements.

    A failure before admission is saved without launching anything. There is
    intentionally no override to accept a synthetic lifetime coverage receipt.
    """
    directory = Path(directory)
    if (not directory.is_absolute() or directory.exists() or
            any(part.casefold() == ".resource-sentinel" for part in directory.parts)):
        raise MeasurementBlocked("ab_new_absolute_evidence_directory_required")
    for ancestor in (directory.parent, *directory.parent.parents):
        info = ancestor.lstat()
        if not ancestor.is_dir() or ancestor.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise MeasurementBlocked("ab_evidence_parent_redirected")
    directory.mkdir(parents=False)
    admission = None
    output = {"schema_version": 1, "artifact_type": "p6_raw_fixture_observation",
              "status": "blocked", "reason": None, "fixture": asdict(spec),
              "ab_record_produced": False, "promotion_permitted": False}
    pending = None
    try:
        _require_platform()
        admission = _real_admission(spec)
        pins = _source_state()
        pins["power_plan_sha256"] = _power_plan()
        output = WindowsFixtureObserver(directory, spec).measure(admission)
        output["pins"] = pins
    except Exception as error:
        output["reason"] = getattr(error, "reason", type(error).__name__)
    finally:
        if admission is not None:
            # The provider owns positive cleanup verification and keeps any
            # uncertainty retained. No release-on-root-exit heuristic here.
            try:
                admission.finish()
            except Exception as error:
                reason = getattr(error, "reason", type(error).__name__)
                output.update(status="pending", reason=reason, admission_cleanup_settled=False)
                pending = PendingAdmissionCleanup(admission, directory, output, reason)
    _write_new(directory / "raw-run.json", output)
    if pending is not None:
        raise pending
    return output


def build_parser():
    parser = argparse.ArgumentParser(description="P6 schedule and gated native raw measurements; adaptive remains off")
    commands = parser.add_subparsers(dest="command", required=True)
    schedule = commands.add_parser("schedule", help="Pin all 7 scenarios and 3 comparisons before measurement")
    schedule.add_argument("--seed", required=True)
    schedule.add_argument("--pairs", type=int, default=MIN_PAIRS_PER_SCENARIO)
    schedule.add_argument("--output", required=True, type=Path)
    analyze = commands.add_parser("analyze", help="Strict paired evidence report; never activates a host")
    analyze.add_argument("--schedule", required=True, type=Path)
    analyze.add_argument("--records", required=True, type=Path)
    analyze.add_argument("--noise", type=Path)
    analyze.add_argument("--output", required=True, type=Path)
    register = commands.add_parser("register-matrix", help="Pin all source, scenario and run identities before native work")
    register.add_argument("--seed", required=True)
    register.add_argument("--pairs", type=int, default=10)
    register.add_argument("--profile-file", type=Path, required=True)
    register.add_argument("--capability-bundle", type=Path, required=True)
    register.add_argument("--baseline-source-manifest", type=Path, required=True)
    register.add_argument("--cache-state", choices=("warm", "cold"), default="warm")
    register.add_argument("--output", type=Path, required=True)
    matrix = commands.add_parser("run-matrix", help="Execute the whole paired matrix through original native authorities")
    matrix.add_argument("--registration", type=Path, required=True)
    matrix.add_argument("--evidence-dir", type=Path, required=True)
    measure = commands.add_parser("measure-fixture", help="Observe a bounded public command after real continuous admission")
    measure.add_argument("--scenario", choices=[name for name, _ in DEFAULT_SCENARIOS], required=True)
    measure.add_argument("--evidence-dir", type=Path, required=True)
    measure.add_argument("--tasks", type=int, default=1)
    measure.add_argument("--units", type=int, required=True)
    measure.add_argument("--memory-mib", type=int, default=128)
    measure.add_argument("--seconds", type=int, default=90)
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "schedule":
            schedule = build_schedule(DEFAULT_SCENARIOS, args.seed, args.pairs)
            _write_new(args.output, {"schema_version": 2, "seed": schedule.seed,
                       "pairs_per_scenario": schedule.pairs_per_scenario,
                       "slots": [asdict(slot) for slot in schedule.slots],
                       "measured": False, "promotion_permitted": False})
            print(json.dumps({"status": "schedule_written", "paired_slots": len(schedule.slots)}))
            return 0
        if args.command == "analyze":
            print(json.dumps(analyze_files(args.schedule, args.records, args.noise, args.output)))
            return 0
        if args.command == "register-matrix":
            from tests.benchmarks.adaptive_orchestrator import create_registration, required_episodes
            registration = create_registration(root=ROOT, order_seed=args.seed, pairs_per_scenario=args.pairs,
                profile_path=args.profile_file, capability_bundle=args.capability_bundle,
                baseline_source_manifest=args.baseline_source_manifest, cache_state=args.cache_state)
            _write_new(args.output, asdict(registration))
            print(json.dumps({"status": "registered", "registration_sha256": registration.sha256,
                              "episodes": len(required_episodes(registration)), "promotion_permitted": False}))
            return 0
        if args.command == "run-matrix":
            from tests.benchmarks.adaptive_orchestrator import MatrixUnsettled, parse_registration, run_native_matrix
            registration = parse_registration(_read_json(args.registration))
            try:
                result = run_native_matrix(registration, args.evidence_dir)
            except MatrixUnsettled as pending:
                try:
                    print(json.dumps({"status": "pending", "reason": pending.reason,
                                      "original_native_owner_retained": True}), flush=True)
                except BaseException:
                    # A lost console must not discard the native owner while
                    # the original authority is restoring/draining its scope.
                    pass
                while True:
                    try:
                        if pending.recover_once():
                            return 3
                        time.sleep(1)
                    except (Exception, KeyboardInterrupt):
                        try:
                            time.sleep(1)
                        except KeyboardInterrupt:
                            pass
            print(json.dumps(result))
            return 0
        spec = FixtureSpec(args.scenario, args.tasks, args.units, args.memory_mib, args.seconds)
        result = run_raw_fixture(args.evidence_dir, spec)
        print(json.dumps({"status": result["status"], "reason": result.get("reason"),
                          "ab_record_produced": False, "promotion_permitted": False}))
        return 0 if result["status"] == "observed" else 3
    except PendingAdmissionCleanup as pending:
        print(json.dumps({"status": "pending", "reason": pending.reason,
                          "original_admission_scope_retained": True}), flush=True)
        # No second workload or replacement scope. An interrupted observer must
        # not abandon the original daily reservation's cleanup witness.
        while True:
            try:
                pending.retry()
                return 3
            except (Exception, KeyboardInterrupt):
                try:
                    time.sleep(1)
                except KeyboardInterrupt:
                    pass
    except Exception as error:
        print(json.dumps({"status": "blocked", "reason": getattr(error, "reason", type(error).__name__),
                          "ab_record_produced": False, "promotion_permitted": False}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
