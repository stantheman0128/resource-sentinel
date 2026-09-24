"""Serial S1 case custody using the actual daily experiment APIs.

This module neither publishes capability evidence nor unlocks the native entry.
The separately attested runner uses an original case's ExperimentNativeScope
directly for launch/control/measurement. Recovery never performs those actions.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import stat
import sys
import threading
from uuid import uuid4

from sentinel.coordinator import Coordinator
from sentinel.adaptive import daily_generation
from sentinel.adaptive.capability_evidence import LiveCapabilityContext
from sentinel.adaptive.contracts import ResourceDemand
from sentinel.adaptive.experiment_abandon import ExperimentUnadmittedCleanup
from sentinel.adaptive.experiment_cleanup import ExperimentAdmissionSettlement, ExperimentReleaseOperation
from sentinel.adaptive.experiment_demand import BeforeNativeCompletion, DailyExperimentDemand, ExperimentDeclaration
from sentinel.adaptive.experiment_scope import ExperimentNativeScope, NativeScopeCompletion
from tests.windows.adaptive_scope_launch import FixtureSource, ScopeCommand


_NEW = object()
_PROVIDERS = {}
_KINDS = frozenset({"round", "self_stop", "empty_probe", "foreign_parent"})
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "adaptive_scope_cpu_worker.py"


class S1ProviderError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.s1_case_owner = reason, owner
        super().__init__(reason)


def _fail(reason, owner=None):
    raise S1ProviderError("s1_provider_" + reason, owner)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _directory(path):
    path = Path(path)
    if not path.is_absolute():
        _fail("absolute_directory_required")
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            _fail("directory_redirected")
    if not path.is_dir():
        _fail("directory_required")
    return path.resolve(strict=True)


def _identity(path):
    info = path.stat()
    return int(info.st_dev), int(info.st_ino)


def _base_python():
    executable = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    if (executable.name.casefold() in {"py.exe", "pyw.exe"} or
            Path(sys.executable).resolve(strict=True) != executable):
        _fail("direct_base_python_required")
    return executable


def _resources(context, kind):
    count = context.logical_processors
    if kind == "round":
        target = count * .25
        workers = math.ceil((target + max(.15, target * .1) + .25) / .9)
        if workers > count:
            _fail("saturation_not_feasible")
    else:
        workers = 1
    return workers, ResourceDemand(float(min(count, workers + 1)), 1 << 30, 1 << 30, 0)


def _capture_generation(case):
    """Read consistency pins through a positively closed original authority.

    These pins cannot grant capacity or survive as readiness authority. Actual
    admission and native preparation acquire their own original daily proof.
    """
    source, data = daily_generation.daily_locations()
    ledger = (data / "sentinel.db").resolve(strict=True)
    case._source_enter_attempted = True
    with daily_generation.readiness_scope(ledger) as original:
        case._source_readiness = original
        if type(original) is not daily_generation._ReadinessScope or type(original.row) is not dict:
            _fail("original_source_scope_required", case)
        row = dict(original.row)
        if row.get("source_root") != str(source.resolve(strict=True)):
            _fail("canonical_source_changed", case)
        daily_generation.revalidate_scoped_readiness(ledger, expected_generation=row)
        encoded = _canonical(row)
    if original.closed is not True or original.error is not None:
        _fail("source_cleanup_unverified", case)
    return encoded


@dataclass(frozen=True)
class S1CaseDeclaration:
    experiment_id: str
    scope_id: str
    creation_nonce: str
    kind: str
    directory: Path
    directory_identity: tuple[int, int]
    generation_json: str
    command: ScopeCommand
    declaration: ExperimentDeclaration
    workers: int
    seconds: int


class S1SerialProvider:
    """One thread, original provider, and unresolved case at a time.

    ``context`` is a typed workload denominator, never a capacity grant. There
    is deliberately no callback, alternate ledger, policy or status argument.
    The console's aggregate source attestation is a separate prerequisite.
    """
    def __init__(self, directory, context, *, bootstrap=None):
        if type(self) is not S1SerialProvider or type(context) is not LiveCapabilityContext:
            _fail("exact_provider_and_context_required")
        self.directory = _directory(directory)
        self.context = context
        if bootstrap is not None:
            from tests.windows.adaptive_producer_bootstrap import ProducerBootstrap
            if type(bootstrap) is not ProducerBootstrap:
                _fail("exact_bootstrap_required")
        self._bootstrap = bootstrap
        self._original_bootstrap = bootstrap
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._immutable = self.directory, self.context, _identity(self.directory)
        self._cases = []
        self._current = None
        _PROVIDERS[id(self)] = self

    def _original(self, *, filesystem=True):
        if (type(self) is not S1SerialProvider or _PROVIDERS.get(id(self)) is not self or
                self._thread is not threading.current_thread() or self._pid != os.getpid() or
                (self.directory, self.context) != self._immutable[:2] or
                self._bootstrap is not self._original_bootstrap):
            _fail("original_provider_required")
        if filesystem and _identity(_directory(self.directory)) != self._immutable[2]:
            _fail("provider_directory_changed")

    def _attest(self, generation=None):
        # Only new capture/admission depends on source attestation. Original
        # restoration/release must still run when source files later change.
        self._original()
        if self._bootstrap is not None:
            self._bootstrap.assert_unchanged()
            binding = self._bootstrap.source_binding
            if generation is not None and (generation.get("source_digest") != binding.source_digest or
                    Path(generation.get("source_root", "")) != self._bootstrap.runtime_root):
                _fail("bootstrap_generation_changed")

    @property
    def current_case(self):
        self._original(filesystem=False)
        return self._current

    @property
    def completed_cases(self):
        self._original(filesystem=False)
        return tuple(case for case in self._cases if case._closed)

    def start_case(self, kind="round"):
        self._attest()
        if type(kind) is not str or kind not in _KINDS:
            _fail("case_kind_invalid")
        if self._current is not None and not self._current._closed:
            _fail("previous_case_unsettled", self._current)
        case = S1Case(self, kind, _token=_NEW)
        # Publish before source readiness, directory creation, capture or SQL.
        self._cases.append(case)
        self._current = case
        try:
            case._capture()
        except BaseException as error:
            case._retain(error)
            case._cleanup_only = True
            raise
        return case

    def recover_once(self):
        self._original(filesystem=False)
        return None if self._current is None else self._current.recover_once()


class S1Case:
    def __init__(self, provider, kind, *, _token=None):
        if _token is not _NEW or type(provider) is not S1SerialProvider:
            _fail("original_case_factory_required")
        self.provider, self.kind = provider, kind
        self.experiment_id, self.scope_id, self.creation_nonce = str(uuid4()), str(uuid4()), uuid4().hex
        self.directory = provider.directory / self.experiment_id
        self.spec = self.demand = self.coordinator = self.scope = None
        self.completion = self.release_operation = self.settlement = self.abandon_operation = None
        self._source_readiness = None
        self._source_enter_attempted = False
        self._capture_entered = self._capture_returned = False
        self._coordinator_entered = self._coordinator_returned = False
        self._admission_entered = self._admission_failed = self._admitted = False
        self._prepare_entered = self._cleanup_only = self._closed = False
        self._demand_original = self._coordinator_original = self._spec_original = None
        self._scope_original = self._completion_original = self._release_original = None
        self._snapshot = None
        self._unsubmitted_close_attempted = False
        self._result_json = None
        self._stop_requested = False
        self.errors = []
        self._binding = (provider, kind, self.experiment_id, self.scope_id, self.creation_nonce, self.directory)

    def _original(self, *, cleanup=False):
        self.provider._original(filesystem=not cleanup)
        if (type(self) is not S1Case or not any(item is self for item in self.provider._cases) or
                self._binding != (self.provider, self.kind, self.experiment_id, self.scope_id,
                                  self.creation_nonce, self.directory) or
                self.spec is not self._spec_original or self.demand is not self._demand_original or
                self.coordinator is not self._coordinator_original or self.scope is not self._scope_original or
                self.completion is not self._completion_original or self.release_operation is not self._release_original):
            _fail("original_case_changed", self)
        if self._closed and self.release_operation is not None:
            # A later read-only evidence observation can itself retain an
            # uncertain SQL close on the same original release operation.
            # The earlier release flag must not hide that new custody.
            if type(self.release_operation) is not ExperimentReleaseOperation:
                _fail("original_release_required", self)
            self.release_operation._original()

    def _retain(self, error):
        if not any(value is error for value in self.errors):
            self.errors.append(error)
        error.s1_case_owner = self

    @property
    def cleanup_result(self):
        self._original(cleanup=True)
        if not self._closed:
            _fail("case_unsettled", self)
        return json.loads(self._result_json)

    def _capture(self):
        generation_json = _capture_generation(self)
        row = json.loads(generation_json)
        self.provider._attest(row)
        daily = Path(row["ledger_path"]).parent
        if self.provider.directory == daily or daily in self.provider.directory.parents:
            _fail("isolated_directory_required", self)
        self.directory.mkdir(exist_ok=False)
        _directory(self.directory)
        workers, requested = _resources(self.provider.context, self.kind)
        seconds = {"self_stop": 2, "empty_probe": 1, "foreign_parent": 5, "round": 115}[self.kind]
        fixture = FixtureSource.capture(_FIXTURE)
        arguments = ("-I", fixture.path, "--canonical-root", row["source_root"],
            "--source-generation", row["generation"], "--source-digest", row["source_digest"],
            "--fixture-sha256", fixture.sha256, "--directory", str(self.directory),
            "--seconds", str(seconds), "--workers", str(workers),
            "--job-name", "Local\\ResourceSentinel.Test.Job." + self.creation_nonce,
            "--nonce", self.creation_nonce, "--scope-id", self.scope_id, "--scope-bound-stdin")
        if self.kind == "foreign_parent":
            arguments += ("--probe-foreign-host",)
        command = ScopeCommand.capture(application=_base_python(), arguments=arguments,
            cwd=self.directory, fixture_paths=(fixture.path,))
        if command.fixture_sources != (fixture,):
            _fail("fixture_changed", self)
        declaration = ExperimentDeclaration(self.experiment_id, "S1", command.sha256, requested)
        self.spec = self._spec_original = S1CaseDeclaration(self.experiment_id, self.scope_id,
            self.creation_nonce, self.kind, self.directory, _identity(self.directory), generation_json,
            command, declaration, workers, seconds)
        self._capture_entered = True
        try:
            demand = DailyExperimentDemand.capture(declaration, self.directory)
        except BaseException as error:
            partial = getattr(error, "experiment_demand_owner", None)
            if type(partial) is DailyExperimentDemand:
                self.demand = self._demand_original = partial
            raise
        self.demand = self._demand_original = demand
        if type(demand) is not DailyExperimentDemand:
            _fail("original_capture_required", self)
        demand._static_original()
        self._snapshot = demand._snapshot
        self._capture_returned = True
        if str(demand.ledger_path) != row["ledger_path"] or str(demand._source_root) != row["source_root"]:
            _fail("captured_daily_source_changed", self)
        # __new__ publication keeps even an interrupted constructor's original
        # SQL/error graph. It never authorizes a replacement constructor retry.
        self.coordinator = self._coordinator_original = Coordinator.__new__(Coordinator)
        self._coordinator_entered = True
        Coordinator.__init__(self.coordinator, demand.ledger_path.parent)
        self._coordinator_returned = True

    def poll_admission(self):
        self._original()
        if (self._cleanup_only or self._closed or self._admission_failed or self._admitted or
                not self._capture_returned or not self._coordinator_returned):
            _fail("admission_not_available", self)
        try:
            self.spec.command.verify()
            self.provider._attest(json.loads(self.spec.generation_json))
            # Publish uncertainty before the original API can acquire/commit.
            # Its SQL/guard cleanup may finish before an outer reply or local
            # result assignment is interrupted. That still requires original
            # settlement, never inferred absence or a second admission call.
            self._admission_failed = True
            self._admission_entered = True
            result = self.coordinator.admit_experiment(self.demand)
            self._classify_admission(result)
            if self._admitted:
                if _canonical(self.demand._original_generation_binding()) != self.spec.generation_json:
                    _fail("admitted_generation_changed", self)
                self._prepare_entered = True
                try:
                    owner = ExperimentNativeScope.prepare(self.demand, self.spec.command,
                        scope_id=self.scope_id, creation_nonce=self.creation_nonce)
                finally:
                    # Registration precedes factories and survives no return.
                    partial = self.demand._native_preparation
                    if partial is not None:
                        self.scope = self._scope_original = partial
                if type(owner) is not ExperimentNativeScope or owner is not self.scope:
                    _fail("original_scope_required", self)
                self.demand._assert_native_preparation(owner)
            return result
        except BaseException as error:
            self._cleanup_only = True
            self._retain(error)
            raise

    def _classify_admission(self, result):
        if type(result) is not dict or type(result.get("allowed")) is not bool:
            _fail("admission_result_unverified", self)
        self._admitted = result["allowed"]
        # Last: an interruption after the preceding assignment still retains
        # the original completed submission for cleanup-only settlement.
        self._admission_failed = False

    def _stop(self):
        if _identity(_directory(self.directory)) != self.spec.directory_identity:
            _fail("case_directory_changed", self)
        marker = self.directory / "stop"
        try:
            with marker.open("xb"):
                pass
        except FileExistsError:
            info = marker.lstat()
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or
                    getattr(info, "st_file_attributes", 0) & 0x400):
                _fail("stop_marker_redirected", self)

    def _finish(self, result):
        if self.demand._closed is not True or self.demand._admission._closed is not True:
            _fail("daily_cleanup_unverified", self)
        self._result_json = _canonical(result)
        self._closed = True
        return self.cleanup_result

    def recover_once(self):
        """One original cleanup tick. Errors retain custody and remain failures.

        ``None`` means the original native scope is still draining. Exceptions
        also leave this exact case retained; a caller must not start another.
        """
        self._original(cleanup=True)
        if self._closed:
            return self.cleanup_result
        self._cleanup_only = True
        try:
            if not self._capture_entered:
                original = self._source_readiness
                source_closed = (type(original) is daily_generation._ReadinessScope and
                    original.closed is True and original.error is None)
                if (self.demand is not None or self._coordinator_entered or
                        self._source_enter_attempted and not source_closed):
                    _fail("partial_source_unsettled", self)
                # Positive no-entry or this exact source owner's positive close
                # accounts for all pre-capture effects. This failed observation
                # is neither an S1 result nor cancellation of any daily claim.
                self._result_json = _canonical(dict(state="NO_DEMAND_CAPTURED",
                    cleanup_complete=True, demand_captured=False, launch_authorized=False))
                self._closed = True
                return self.cleanup_result
            if not self._capture_returned or (self._coordinator_entered and not self._coordinator_returned):
                _fail("partial_factory_unsettled", self)
            if not self._admission_entered:
                self._unsubmitted_close_attempted = True
                if not (self.demand._closed is True and self.demand._admission._closed is True):
                    self.demand.close_unsubmitted()
                return self._finish(dict(state="NOT_SUBMITTED", cancelled=True,
                    execution_id=self._snapshot.execution_id,
                    launch_authorized=False))
            if self._admission_failed:
                try:
                    observation = self.coordinator.settle_experiment_admission(self.demand)
                finally:
                    self.settlement = self.demand._admission_settlement
                if (type(self.settlement) is not ExperimentAdmissionSettlement or
                        self.settlement.demand is not self.demand or self.settlement._settled is not True or
                        type(observation) is not dict or observation.get("settled") is not True):
                    _fail("settlement_unverified", self)
                state = observation.get("state")
                if state in {"RESERVED", "EXPIRED_HOLD"}:
                    self._admitted = True
                elif state not in {"QUEUED", "NEVER_SUBMITTED", "SUBMISSION_REJECTED"}:
                    _fail("admission_state_unverified", self)
                self._admission_failed = False
            if not self._admitted:
                try:
                    result = self.coordinator.abandon_experiment(self.demand)
                finally:
                    self.abandon_operation = self.demand._unadmitted_cleanup
                operation = self.abandon_operation
                if (type(operation) is not ExperimentUnadmittedCleanup or operation.demand is not self.demand or
                        operation._completed is not True or result.get("cancelled") is not True or
                        result.get("state") not in {"NOT_SUBMITTED", "QUEUED_CANCELLED", "SUBMISSION_REJECTED"}):
                    _fail("abandon_unverified", self)
                return self._finish(result)
            if self.completion is None:
                if self._prepare_entered:
                    if type(self.scope) is not ExperimentNativeScope:
                        _fail("preparation_owner_unavailable", self)
                    self.demand._assert_native_preparation(self.scope)
                    # close_native restores first where applicable, including
                    # partial preparation which cannot safely call restore yet.
                    if not self._stop_requested:
                        try:
                            self._stop()
                            self._stop_requested = True
                        except BaseException as error:
                            # A failed voluntary marker cannot prevent original
                            # native restore/drain. Keep it as a failed run even
                            # if the bounded workload subsequently exits itself.
                            self._retain(error)
                    completion = self.scope.close_native()
                    if completion is None:
                        return None
                    if type(completion) is not NativeScopeCompletion or completion.owner is not self.scope:
                        _fail("original_native_completion_required", self)
                else:
                    completion = self.demand.seal_without_native()
                    if type(completion) is not BeforeNativeCompletion or completion.owner is not self.demand:
                        _fail("original_before_native_required", self)
                completion.assert_original()
                self.completion = self._completion_original = completion
            if self.release_operation is None:
                try:
                    operation = self.demand.prepare_release(self.completion)
                finally:
                    self.release_operation = self._release_original = self.demand._release_operation
                if operation is not self.release_operation:
                    _fail("original_release_required", self)
            operation = self.release_operation
            if (type(operation) is not ExperimentReleaseOperation or operation.demand is not self.demand or
                    operation.completion is not self.completion):
                _fail("original_release_required", self)
            result = self.coordinator.release_experiment(operation)
            if operation._completed is not True or result.get("released") is not True:
                _fail("release_unverified", self)
            return self._finish(result)
        except BaseException as error:
            self._retain(error)
            raise
