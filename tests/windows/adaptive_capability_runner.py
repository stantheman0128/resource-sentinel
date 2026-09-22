"""Native S1 producer and immutable evidence-run bookkeeping.

This is an external-console test runner, not a deployment or admission bypass.
Every new native experiment first obtains the real continuous-admission owner.
The presently unavailable daily cohort therefore returns BLOCKED before a Job
is created. Unit tests of the reducers/bookkeeping establish no Windows gate.

The S1 owner is the existing isolated P1 launcher/controller, with an actual
same-host reservation, protected Job and recovery journal. No duration, round
count, target or admission estimate is configurable from the command line.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import time
from uuid import uuid4

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive.contracts import ResourceDemand, strict_json_loads
from sentinel.adaptive.sampler import profile_revision


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "adaptive_cpu_worker.py"
WINDOW_NS = 30_000_000_000
ROUNDS = 10
MAX_FILE_BYTES = 256 * 1024


class NativeRunBlocked(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class NativeRunUnsettled(NativeRunBlocked):
    """The external-console owner must remain alive and retain ``coverage``.

    This is not a retry token and cannot be serialized into a fresh owner.
    Recovery uses the original runtime's same handles and admitted contexts.
    """
    def __init__(self, coverage, *, additional_custody=None):
        super().__init__("native_run_custody_unsettled")
        self.coverage = coverage
        self.additional_custody = additional_custody


def custody_pending(coverage):
    return bool(coverage.pending_admissions or
                any(not owner._closed for owner in coverage.owners))


def error_evidence(error, *, stage):
    """Bounded safe API diagnostics, never arbitrary exception text/paths."""
    rows, seen = [], set()
    current = error
    while current is not None and len(rows) < 4 and id(current) not in seen:
        seen.add(id(current))
        reason = getattr(current, "reason", None)
        if type(reason) is not str or re.fullmatch(r"[a-z][a-z0-9_.:]{0,127}", reason) is None:
            reason = "native_error"
        code = getattr(current, "win32_error", getattr(current, "winerror", None))
        if type(code) is not int or not 0 <= code <= 0xffffffff:
            code = None
        rows.append(dict(stage=stage, type=type(current).__name__, reason=reason, win32_error=code))
        current = current.__cause__ or current.__context__
    return rows


def infrastructure_membership(owner, job):
    # ManagedAdmission already retains the original exact current wrapper.
    # Borrow it; opening an extra observation handle adds avoidable close risk.
    current = owner.admission._process
    if current.identity != owner.caller:
        raise NativeRunBlocked("native_infrastructure_identity_changed")
    membership = current.is_in_job(job.handle)
    if type(membership) is not bool:
        raise NativeRunBlocked("native_infrastructure_membership_unknown")
    return membership, current.identity.to_dict()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _write_new(path, value):
    """Never replace prior measurements, including after a failed run."""
    raw = canonical(value)
    if len(raw) > MAX_FILE_BYTES:
        raise NativeRunBlocked("native_artifact_oversized")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def base_python():
    """Use the actual installed interpreter, never the Windows py launcher."""
    executable = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    if executable.name.casefold() in {"py.exe", "pyw.exe"}:
        raise NativeRunBlocked("native_base_python_required")
    if Path(sys.executable).resolve(strict=True) != executable:
        raise NativeRunBlocked("native_direct_base_python_required")
    return executable


def _directory(directory):
    directory = Path(directory)
    if not directory.is_absolute():
        raise NativeRunBlocked("native_evidence_absolute_path_required")
    production = (Path.home() / ".resource-sentinel").resolve()
    resolved = directory.resolve()
    if resolved == production or production in resolved.parents:
        raise NativeRunBlocked("native_evidence_must_be_isolated")
    directory.mkdir(parents=True, exist_ok=True)
    evidence._safe_directory(directory)
    return directory


def s1_resources(logical_processors):
    if type(logical_processors) is not int or not 1 <= logical_processors <= 64:
        raise NativeRunBlocked("native_denominator_invalid")
    target = logical_processors * .25
    tolerance = max(.15, target * .1)
    workers = math.ceil((target + tolerance + .25) / .9)
    if workers > logical_processors:
        raise NativeRunBlocked("native_saturation_not_feasible")
    return workers, ResourceDemand(float(min(logical_processors, workers + 1)),
                                   1 << 30, 1 << 30, 0)


def _raw_window(job, owner, *, capped=False):
    # Read native integer CPU counters; do not invert a rounded seconds value.
    initial = job._native.accounting()
    start = time.monotonic_ns()
    if start + WINDOW_NS > int(owner.observation_deadline * 1_000_000_000):
        raise NativeRunBlocked("native_fixed_window_deadline")
    if capped:
        owner.wait_capped(WINDOW_NS / 1_000_000_000)
    else:
        while True:
            remaining = (start + WINDOW_NS - time.monotonic_ns()) / 1_000_000_000
            if remaining <= 0:
                break
            # The uncapped floor must also remain genuinely covered.
            owner.authority.assert_ready()
            owner._assert_covered(owner.store.query(owner.execution_id))
            time.sleep(min(.25, remaining))
    final = job._native.accounting()
    end = time.monotonic_ns()
    return dict(start_ns=start, end_ns=end, cpu_start_100ns=initial.cpu_100ns,
                cpu_end_100ns=final.cpu_100ns,
                members_start=initial.active_processes, members_end=final.active_processes)


def _ready(directory, job, workers, deadline):
    until = min(deadline, time.monotonic() + 10)
    while time.monotonic() < until:
        records = [strict_json_loads(path.read_bytes()) for path in directory.glob("ready-*.json")]
        if len(records) == workers:
            expected = {row["pid"] for row in records}
            if (len(expected) != workers or expected != set(job.active_pids()) or
                    any(row["nonce"] != job.nonce or row["in_expected_job"] is not True
                        for row in records)):
                raise NativeRunBlocked("native_earliest_membership_mismatch")
            return records
        time.sleep(.05)
    raise NativeRunBlocked("native_fixture_readiness_deadline")


def _live_allocations(owner):
    # Explicit read-only inspection, never Coordinator construction/migration.
    uri = Path(owner.store.db_path).resolve(strict=True).as_uri() + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=.5)
    try:
        return sum(connection.execute(
            f"SELECT count(*) FROM {table} WHERE execution_id=?",
            (owner.execution_id,)).fetchone()[0]
            for table in ("reservations", "worker_reservations"))
    finally:
        connection.close()


def cleanup_case(owner, job, directory):
    """Native restore/query, voluntary stop, positive empty, archive, close.

    Unknown close outcomes retain the original owner; no second native Close,
    fabricated receipt, cancellation or process kill can establish completion.
    """
    errors = []
    result = {}
    try:
        owner.restore()
        observed = owner.job.query_cpu()
        result["cpu_flags"] = observed["flags"]
        if observed["flags"] & 1:
            raise NativeRunBlocked("native_cleanup_cap_still_enabled")
    except BaseException as error:
        errors.append(error)
    try:
        (directory / "stop").touch(exist_ok=True)
    except BaseException as error:
        errors.append(error)
    try:
        if not owner.job.wait_empty(max(0, owner.observation_deadline - time.monotonic())):
            raise NativeRunBlocked("native_cleanup_job_not_empty")
        remaining = owner.job._native.accounting().active_processes
        if owner.job.active_pids() or remaining:
            raise NativeRunBlocked("native_cleanup_membership_unverified")
        result["active_processes"] = remaining
    except BaseException as error:
        errors.append(error)
    if not errors:
        try:
            terminal = owner.finalize()
            if terminal["state"] not in {"FINISHED", "CANCELLED_BEFORE_START"}:
                raise NativeRunBlocked("native_cleanup_lifecycle_unsettled")
            record = owner.journal.read(owner.execution_id, creation_nonce=owner.creation_nonce)
            result["pending_intents"] = int(record.pending_intent is not None)
            result["live_allocations"] = _live_allocations(owner)
            if result["pending_intents"] or result["live_allocations"]:
                raise NativeRunBlocked("native_cleanup_bookkeeping_unsettled")
            owner.close()
            result["unsettled_handles"] = int(not owner._closed)
            if result["unsettled_handles"]:
                raise NativeRunBlocked("native_cleanup_custody_unsettled")
        except BaseException as error:
            errors.append(error)
    if errors:
        owner._retain()
        failure = NativeRunBlocked("native_cleanup_unverified")
        for error in errors:
            failure.add_note(type(error).__name__)
        raise failure from errors[0]
    evidence._cleanup(result)
    return result


class S1Producer:
    def __init__(self, coverage, directory, context):
        self.coverage, self.directory, self.context = coverage, directory, context
        self.python = base_python()
        self.native = coverage.native

    def _open(self, name, *, seconds=115, workers=1, foreign=False, resources=None):
        directory = self.directory / name
        directory.mkdir()
        nonce = uuid4().hex
        command = subprocess.list2cmdline([str(self.python), str(FIXTURE),
            "--nonce", nonce, "--job-name", self.native.JOB_PREFIX + nonce,
            "--directory", str(directory), "--seconds", str(seconds),
            "--workers", str(workers)] + (["--probe-foreign-host"] if foreign else []))
        requested = resources or ResourceDemand(float(min(self.context.logical_processors, workers + 1)),
                                               1 << 30, 1 << 30, 0)
        _write_new(directory / "case-start.json", dict(case=name, nonce=nonce,
            started_ns=time.monotonic_ns(), requested=requested.to_dict(), workers=workers,
            workload_maximum_seconds=seconds, observation_deadline_seconds=120))
        owner = self.coverage.open_case(command=command, cwd=str(directory),
            directory=directory, requested=requested, creation_nonce=nonce)
        job = owner.prepare()
        return owner, job, command, directory

    def _launch(self, owner, command, directory):
        import msvcrt
        with open(os.devnull, "rb") as source, open(os.devnull, "wb") as sink:
            return owner.launch_once(str(self.python), command, cwd=str(directory),
                stdin_handle=msvcrt.get_osfhandle(source.fileno()),
                stdout_handle=msvcrt.get_osfhandle(sink.fileno()),
                stderr_handle=msvcrt.get_osfhandle(sink.fileno()))

    @staticmethod
    def _finish(owner, job, directory, record):
        try:
            record["cleanup"] = cleanup_case(owner, job, directory)
        except BaseException as error:
            record["cleanup_failure"] = {"type": type(error).__name__,
                "reason": "native_cleanup_unverified", "errors": error_evidence(error, stage="cleanup")}
            raise
        finally:
            _write_new(directory / "native-result.json", record)
        return record["cleanup"]

    def _prerequisites(self):
        values = {}
        owner, job, command, directory = self._open("self-stop", seconds=2)
        record = {"case": "self_stop"}
        try:
            start = time.monotonic_ns()
            process = self._launch(owner, command, directory)
            _ready(directory, job, 1, owner.observation_deadline)
            if not process.wait(min(10, max(0, owner.observation_deadline - time.monotonic()))):
                raise NativeRunBlocked("native_self_stop_deadline")
            values["self_stop_elapsed_ns"] = time.monotonic_ns() - start
            values["self_stop_exit_code"] = process.exit_code()
            exit_record = strict_json_loads((directory / f"exit-{process.pid}.json").read_bytes())
            if exit_record["reason"] != "self_deadline" or values["self_stop_exit_code"] != 0:
                raise NativeRunBlocked("native_self_stop_failed")
            record.update(exit=exit_record, root_identity=process.identity())
        finally:
            self._finish(owner, job, directory, record)

        owner, job, _, directory = self._open("empty-restore", seconds=1)
        record = {"case": "empty_restore"}
        try:
            record["limits"] = job.query_limits()
            record["initial"] = job.query_cpu()
            if job.active_pids() or record["limits"] != {"limit_flags": 0, "ui_restrictions": 0}:
                raise NativeRunBlocked("native_empty_job_baseline_invalid")
            record["applied"] = owner.set_cpu_rate(2500)
            job.close()
            job = owner.reopen_probe()
            record["reopened"] = job.query_cpu()
            record["restored"] = owner.restore(through=job)
            evidence._cpu(record["initial"])
            evidence._cpu(record["applied"], rate=2500)
            evidence._cpu(record["reopened"], rate=2500)
            evidence._cpu(record["restored"])
        finally:
            self._finish(owner, job, directory, record)
        values["empty_restore"] = record["cleanup"]

        owner, job, command, directory = self._open("foreign-parent", seconds=5, foreign=True)
        record = {"case": "foreign_parent"}
        try:
            process = self._launch(owner, command, directory)
            if not process.wait(min(10, max(0, owner.observation_deadline - time.monotonic()))):
                raise NativeRunBlocked("native_foreign_parent_deadline")
            record["probe"] = strict_json_loads((directory / "foreign-probe.json").read_bytes())
            probe = record["probe"]
            if (process.exit_code() != 0 or probe["in_expected_job"] is not True or
                    probe["nonce"] != job.nonce or probe["foreign_gate"]["status"] != "unsupported" or
                    "parent Job" not in probe["foreign_gate"]["reason"]):
                raise NativeRunBlocked("native_foreign_parent_not_rejected")
            # The foreign child calls only host preflight; it never attempts a
            # second managed launch. Its own containing Job is directly seen.
            values["foreign_parent_jobs"] = int(probe["in_expected_job"])
            values["foreign_parent_launches"] = 0
        finally:
            self._finish(owner, job, directory, record)
        return values

    def _round(self, iteration):
        workers, resources = s1_resources(self.context.logical_processors)
        owner, job, command, directory = self._open(f"effect-{iteration:02d}", workers=workers,
                                                  resources=resources)
        row = dict(iteration=iteration, nonce=job.nonce,
                   denominator=self.context.logical_processors, rate_bp=2500, worker_count=workers)
        details = {"requested": resources.to_dict(), "disabled_encoding": {"flags": 0, "rate_bp": 10000}}
        try:
            limits = job.query_limits()
            row["initial"] = job.query_cpu()
            evidence._cpu(row["initial"])
            if limits != {"limit_flags": 0, "ui_restrictions": 0}:
                raise NativeRunBlocked("native_job_has_other_limits")
            process = self._launch(owner, command, directory)
            records = _ready(directory, job, workers, owner.observation_deadline)
            details.update(earliest_membership=records, root_identity=process.identity())
            infrastructure_member, details["infrastructure_identity"] = infrastructure_membership(owner, job)
            if infrastructure_member:
                raise NativeRunBlocked("native_infrastructure_in_work_job")
            row["uncapped_window"] = _raw_window(job, owner)
            baseline = evidence._window(row["uncapped_window"])
            target = self.context.logical_processors * .25
            tolerance = max(.15, target * .1)
            if (baseline < workers * .9 or baseline < target + tolerance + .25 or
                    baseline > self.context.logical_processors):
                raise NativeRunBlocked("native_canary_not_saturated")
            row["applied"] = owner.set_cpu_rate(2500)
            evidence._cpu(row["applied"], rate=2500)
            row["capped_window"] = _raw_window(job, owner, capped=True)
            if abs(evidence._window(row["capped_window"]) - target) > tolerance:
                raise NativeRunBlocked("native_cpu_effect_failed")
            job.close()
            job = owner.reopen_probe()
            row["reopened"] = job.query_cpu()
            evidence._cpu(row["reopened"], rate=2500)
            row["restored"] = owner.restore(through=job)
            evidence._cpu(row["restored"])
            row["restored_window"] = _raw_window(job, owner)
            restored = evidence._window(row["restored_window"])
            if restored < baseline * .9 or restored < target + tolerance + .25:
                raise NativeRunBlocked("native_cpu_restore_effect_failed")
            row["containment"] = dict(before_user_code_members=len(records),
                extended_limit_flags=limits["limit_flags"], ui_restrictions=limits["ui_restrictions"],
                reopened_nonce=job.nonce, allowed_logon_id=job.security["allowed_logon_sid"],
                protected_dacl=int(job.security["protected_dacl"]),
                allow_ace_count=job.security["ace_count"], infra_in_work_job=int(infrastructure_member))
        finally:
            raw = {"measurements": row, "details": details}
            row["cleanup"] = self._finish(owner, job, directory, raw)
        return row

    def run(self):
        self.native.require_supported_host()
        data = {"prerequisites": self._prerequisites(), "rounds": []}
        for index in range(ROUNDS):
            data["rounds"].append(self._round(index))
        evidence._s1(data, self.context)
        return data


def produce_s1(coverage, evidence_directory, context):
    """Consume the in-process coverage returned by the actual prerequisite."""
    from tests.windows.adaptive_execution import S1Runtime
    if type(coverage) is not S1Runtime:
        raise NativeRunBlocked("native_continuous_owner_type_invalid")
    if type(context) is not evidence.LiveCapabilityContext:
        raise NativeRunBlocked("native_context_type_invalid")
    return S1Producer(coverage, Path(evidence_directory), context).run()


class NativeEvidenceRun:
    """One frozen host/build/profile run, reusable by the gate orchestrator.

    A partial bundle is intentionally valid JSON but has missing gates; the
    production authority refuses it. Resuming requires the exact same current
    native context and source bytes. No command imports arbitrary gate JSON.
    """
    def __init__(self, directory, profile):
        if os.name != "nt":
            raise NativeRunBlocked("native_windows_required")
        base_python()
        self.directory = _directory(directory)
        self.profile = profile
        self.context_source = evidence.NativeContextSource()
        self.build_source = evidence.CurrentBuildSource()
        self.context, self.build = self.context_source(), self.build_source()
        self.revision = profile_revision(profile)
        self.run_path = self.directory / "run.json"
        if self.run_path.exists():
            payload, _ = evidence._read(self.run_path, MAX_FILE_BYTES)
            self.record = strict_json_loads(payload)
            expected = {"schema_version", "run_id", "context", "build", "profile_revision"}
            if (type(self.record) is not dict or set(self.record) != expected or
                    self.record["schema_version"] != 1):
                raise NativeRunBlocked("native_run_schema_invalid")
            evidence._uuid(self.record["run_id"])
            self._assert_record()
        else:
            self.record = dict(schema_version=1, run_id=str(uuid4()), context=asdict(self.context),
                               build=asdict(self.build), profile_revision=self.revision)
            _write_new(self.run_path, self.record)

    def _assert_record(self):
        if (self.record["context"] != asdict(self.context) or
                self.record["build"] != asdict(self.build) or
                self.record["profile_revision"] != self.revision):
            raise NativeRunBlocked("native_run_provenance_changed")

    def assert_unchanged(self):
        if self.context_source() != self.context or self.build_source() != self.build:
            raise NativeRunBlocked("native_run_provenance_changed")

    def publish_gate(self, gate, data):
        if gate not in {"S1", "S2", "S3", "P4", "P5", "P6"}:
            raise NativeRunBlocked("native_gate_unknown")
        self.assert_unchanged()
        path = self.directory / f"{gate}.json"
        digest = _write_new(path, dict(schema_version=1, run_id=self.record["run_id"],
            gate=gate, evidence_source="native", data=data))
        # Bundle generation uses only this run's exact typed artifact envelope.
        # Its changing hash requires an explicit fresh pin by later consumers.
        references = []
        for name in ("S1", "S2", "S3", "P4", "P5", "P6"):
            artifact = self.directory / f"{name}.json"
            if not artifact.exists():
                continue
            raw, _ = evidence._read(artifact, MAX_FILE_BYTES)
            value = strict_json_loads(raw)
            if (type(value) is not dict or set(value) != {"schema_version", "run_id", "gate", "evidence_source", "data"} or
                    value["schema_version"] != 1 or value["run_id"] != self.record["run_id"] or
                    value["gate"] != name or value["evidence_source"] != "native"):
                raise NativeRunBlocked("native_artifact_run_mismatch")
            references.append(dict(gate=name, path=artifact.name, sha256=hashlib.sha256(raw).hexdigest()))
        bundle = dict(schema_version=1, kind="native_capability_bundle",
            run_id=self.record["run_id"], evidence_source="native", build=asdict(self.build),
            context=asdict(self.context), profile_revision=self.revision, artifacts=references)
        raw = canonical(bundle)
        temporary = self.directory / ("bundle-" + uuid4().hex + ".pending")
        _write_new(temporary, bundle)
        os.replace(temporary, self.directory / "bundle.json")
        return dict(gate=gate, artifact_sha256=digest, bundle_sha256=hashlib.sha256(raw).hexdigest(),
                    measured_gates=[row["gate"] for row in references], promotion=False)

    def run_gate(self, gate):
        if gate not in {"S1", "S2"}:
            raise NativeRunBlocked("native_gate_requires_own_producer")
        if (self.directory / f"{gate}.json").exists():
            raise NativeRunBlocked("native_gate_already_recorded")
        from tests.windows.adaptive_admission import require_continuous_admission
        # This is the only ordinary entry to experimental authority. No fixture
        # receipts, environment booleans or alternate DB construct it here.
        try:
            coverage = require_continuous_admission()
        except BaseException as primary:
            try:
                _write_new(self.directory / (gate + "-blocked-" + uuid4().hex + ".json"),
                    dict(gate=gate, status="blocked", reason="continuous_admission_unavailable",
                         error_type=type(primary).__name__, producer_native_work_started=False,
                         errors=error_evidence(primary, stage="admission"), promotion=False))
            except BaseException:
                primary.add_note("native_prerequisite_evidence_write_failed")
            raise
        directory = None
        try:
            # The real provider may already retain an original reservation or
            # a partial native owner. Failures before the first experiment must
            # preserve it too, including provenance/directory failures.
            self.assert_unchanged()
            directory = self.directory / (gate.lower() + "-raw-" + uuid4().hex)
            directory.mkdir()
            if gate == "S1":
                data = produce_s1(coverage, directory, self.context)
            else:
                from tests.windows.adaptive_launch_producer import produce_s2
                data = produce_s2(coverage, directory, self.context)
                evidence._s2(data, self.context)
            if custody_pending(coverage):
                raise NativeRunUnsettled(coverage)
            return self.publish_gate(gate, data)
        except BaseException as primary:
            try:
                failure_path = (self.directory / (gate + "-failure-" + uuid4().hex + ".json")
                    if directory is None or not directory.is_dir() else directory / "failure.json")
                _write_new(failure_path, dict(gate=gate, status="failed",
                    reason="native_case_failed", error_type=type(primary).__name__,
                    errors=error_evidence(primary, stage="measurement"), promotion=False))
            except BaseException:
                primary.add_note("native_failure_evidence_write_failed")
            if isinstance(primary, NativeRunUnsettled):
                raise
            if custody_pending(coverage):
                raise NativeRunUnsettled(coverage, additional_custody=primary) from primary
            raise
