"""Measured, scoped capability evidence; never a mode or deployment switch.

Producer contract v1 (item 6 must emit this, existing spike JSON is not v1):

* bundle.json has exactly schema_version=1, kind='native_capability_bundle',
  run_id (UUID), evidence_source='native', build (BuildIdentity fields), context
  (LiveCapabilityContext fields), profile_revision, and artifacts. Artifacts is
  a list of {gate, path, sha256}; paths are one local basename, one per gate.
* Each artifact has exactly schema_version=1, run_id, gate, evidence_source,
  and data. Both sources must be native. The same run identity binds the final
  aggregate, not permission to splice an unrelated host/profile's results.
* S1 data is {prerequisites, rounds}. Prerequisites is the three numeric native
  observations described in _s1; rounds are ten unique 0..9 records, with raw
  CPU/window counters, cap/readback/restore and final cleanup observations.
* S2 data is {hosts}, each {name, executable_sha256, measured_topologies,
  cases}; S3 is {cases}. Each S2 case also has topology_sha256 referencing
  its actual original-wrapper observation (null only for infra_exit_125,
  which must not launch). A topology without an actual case is not measured;
  only a topology with its own complete launched-case matrix is control-eligible.
  Partial secondary observations do not inherit another topology's evidence.
  Each case has case, iteration, observations and cleanup.
  Their fixed matrices/observations are declared below; producers must keep the
  original detailed native logs whose fixed producer digest identifies their
  interpretation. A pass boolean cannot replace any numeric observation.
* P4 data uses closed schema_version=2 with {scales, wrapper_cold_ns,
  wrapper_warm_ns, wrapper_telemetry, leak}. Original asynchronous sink offer,
  write and directory observations accompany each scope. Queued report bytes
  are not persisted bytes. The strict idle growth predicate is unchanged.
  Scales contain
  exact monitor identities and CPU endpoints, timestamped Private Commit and waiting-wrapper
  overhead, at 1/10/50 Jobs; 50 is stress outside the allowed <=10 Job scope.
* P5 data is {reaction, helper_loss, guardian_loss, grant_restore, invariants,
  grants}. Times are ordered integer interrupt ticks; no configured interval
  or process-running boolean substitutes for Query-confirmed measurements.
* P6 accepts {pairs} for the explicit formal arithmetic but is not a LIMITED
  authority yet: the harness-only A0/noise clarification has not been promoted
  into a runtime contract. This is a named, honest promotion gap. Earlier gate
  purposes have complete positive verification paths.

All input is bounded strict JSON; a pinned manifest hash, actual runtime and
producer digests, interpreter and current host/logon/topology/profile must
match. Digests establish content/provenance consistency, not proof against a
hostile same-SID forger. This uses the plan's cooperating-process model. An
explicit in-process context/build fixture is a unit-test seam, never a CLI,
JSON or environment override. Tests of this verifier prove no native gate.

No test package is imported by production. The numeric limits here are the
formal plan §§11.2/12.1; percentile uses the cost probe's nearest-rank method.
Neither restriction rejection nor missing evidence prevents owned restoration.

Execution authorization additionally requires a trusted, in-process launch
scope source. Its measured topology must come from the exact pinned S2
artifact and its actual topology from retained provenance of that execution's
original wrapper launch. Choosing two equal hashes is not an implementation.
The current production producer/launcher integration does not provide this
provenance; item 4/6 must add it before injecting a production source. Default
None therefore refuses every restrictive execution even if global gates pass.
There is no JSON, environment or CLI launch-scope authorization switch.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import statistics
import sys
from typing import Mapping
from uuid import UUID

from sentinel.accounting import local_host_identity
from .contracts import ContractViolation, IdentityStatus, MAX_JSON_DEPTH, ProcessIdentity, strict_json_loads
from .decision import PolicyProfile
from .host_authority import read_host_capability
from .identity import VerifiedProcess
from .sampler import profile_revision
from .store import LifecycleError


_ROOT = Path(__file__).resolve().parents[2]
_MAX_BYTES = 256 * 1024
# P4 retains per-process peaks and actual host-loop ticks at all three scales.
# This fixed artifact-only limit is selected by the expected gate before read;
# bundle, other gates, runtime protocols and IPC keep their existing bounds.
_P4_MAX_BYTES = 2 * 1024 * 1024
_MAX_BUILD_FILES = 256
_MAX_BUILD_ENTRIES = 2048
_MAX_BUILD_BYTES = 16 * 1024 * 1024
_TICKS = 10_000_000
_MIB = 1 << 20
_PURPOSES = {
    "isolated_canary": ("S1", "S2", "S3", "P4"),
    "p6_trial": ("S1", "S2", "S3", "P4", "P5"),
    "limited": ("S1", "S2", "S3", "P4", "P5", "P6"),
}
S2_CASES = {
    "exit_0": 3, "exit_7": 3, "child_exit_125": 3, "infra_exit_125": 3,
    "unicode_space": 3, "stdin": 3, "parallel_stdout_stderr": 3,
    "embedded_quotes": 3, "metacharacters": 3, "fast_exit": 20,
    "root_child_survival": 20, "null_stdio": 3, "command_length": 3,
    "ctrl_c": 3, "collector_isolation": 3,
}
S3_CASES = {name: 10 for name in (
    "intent_before", "intent_after_set_before", "set_after_query_before",
    "query_after_audit_before", "root_exit_after", "lease_renewal",
    "grant_commit_restore_before", "guardian_takeover", "guardian_hang",
    "wrapper_loss", "grant_before_cap", "audit_unavailable", "recovery_owner_race",
    "independent_supervisor_recovery",
)}
_ZERO_INVARIANTS = (
    "wrong_pid_mutations", "shared_ui_mutations", "exempt_restrictions",
    "workload_kills", "double_launches", "double_reservations",
    "premature_child_releases", "multiple_caps", "deadline_overruns",
    "stale_sequence_renewals", "intent_order_violations", "sample_fsyncs",
    "active_manifest_rotations", "capped_demand_floor_decreases",
)


class CapabilityEvidenceError(LifecycleError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _reject(reason):
    raise CapabilityEvidenceError(reason)


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _integer(value, *, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _reject("capability_measurement_invalid")
    return value


def _finite(value, *, minimum=0):
    if type(value) not in (int, float) or not math.isfinite(value) or value < minimum:
        _reject("capability_measurement_invalid")
    return value


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _reject("capability_schema_invalid")
    return value


def _list(value, *, minimum=1, maximum=4096):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        _reject("capability_measurement_missing")
    return value


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        if parsed is None or not parsed.int or str(parsed) != value:
            raise ValueError
    except (ValueError, AttributeError):
        _reject("capability_run_identity_invalid")


def _fingerprint(path):
    info = os.lstat(path)
    if (stat.S_ISLNK(info.st_mode) or
            getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400) or
            not stat.S_ISREG(info.st_mode) or not info.st_ino):
        _reject("capability_path_unsafe")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _safe_directory(path):
    for parent in (path, *path.parents):
        info = os.lstat(parent)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
                getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            _reject("capability_path_unsafe")


def _read(path, maximum):
    before = _fingerprint(path)
    if before[2] > maximum:
        _reject("capability_evidence_oversized")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        # Windows lstat and fstat may expose different ctime meanings (the
        # observed host returns creation versus last-write time). File ID,
        # volume, size and mtime must still agree on the opened handle. Compare
        # the full path fingerprint, including ctime, again after the read.
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != before[:4]:
            _reject("capability_evidence_changed")
        payload = stream.read(maximum + 1)
    if len(payload) != before[2] or _fingerprint(path) != before:
        _reject("capability_evidence_changed")
    return payload, before


def _artifact_json_loads(payload, *, expected_gate):
    """Keep the protocol decoder's strictness with one fixed P4 file bound.

    Selection is by the caller's already expected gate. Neither an envelope's
    own gate field nor a pathname can enlarge another artifact or IPC message.
    """
    if expected_gate != "P4":
        return strict_json_loads(payload)
    if not isinstance(payload, (str, bytes)):
        raise ContractViolation("JSON: UTF-8 payload required")
    try:
        size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)
        if size > _P4_MAX_BYTES:
            raise ContractViolation("JSON: message too large")

        def pairs(values):
            result = {}
            for key, value in values:
                if key in result:
                    raise ContractViolation("JSON: duplicate key")
                result[key] = value
            return result

        def invalid_constant(_):
            raise ContractViolation("JSON: nonstandard number")

        def finite_float(text):
            value = float(text)
            if not math.isfinite(value):
                raise ContractViolation("JSON: nonfinite number")
            return value

        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="strict")
        depth, quoted, escaped = 0, False, False
        for char in payload:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise ContractViolation("JSON: nesting too deep")
            elif char in "]}":
                depth -= 1
        result = json.loads(payload, object_pairs_hook=pairs, parse_constant=invalid_constant,
                            parse_float=finite_float)
    except (UnicodeError, ValueError, RecursionError) as error:
        if isinstance(error, ContractViolation):
            raise
        raise ContractViolation("JSON: malformed payload") from None
    if type(result) is not dict:
        raise ContractViolation("JSON: object required")
    return result


def _sha(value):
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class BuildIdentity:
    runtime_sha256: str
    producer_sha256: str

    def __post_init__(self):
        if not _digest(self.runtime_sha256) or not _digest(self.producer_sha256):
            _reject("capability_build_invalid")


class CurrentBuildSource:
    """Hash complete bounded inventories, cache only unchanged fingerprints.

    Runtime includes every shipped sentinel Python module and the command
    adapter. Producer includes all native/benchmark/fixture Python sources.
    This deliberately ignores git HEAD as a substitute for current bytes.
    """
    def __init__(self):
        self._cache = {}
        self._inventories = {}

    def _inventory(self, roots, extras=()):
        key = (tuple(roots), tuple(extras))
        previous = self._inventories.get(key)
        if previous is not None:
            paths, directories = previous
            for directory, stamp in directories.items():
                info = os.lstat(directory)
                if (info.st_dev, info.st_ino, info.st_mtime_ns) != stamp:
                    _reject("capability_build_inventory_changed")
            return self._hash_paths(paths)
        paths, visited = [], 0
        directories = {}
        for root in roots:
            _safe_directory(root)
            pending = [(root, 0)]
            while pending:
                directory, depth = pending.pop()
                if depth > 16:
                    _reject("capability_build_oversized")
                info = os.lstat(directory)
                directories[directory] = (info.st_dev, info.st_ino, info.st_mtime_ns)
                # scandir is streamed: a huge directory is refused before it
                # is materialized, including entries that are not Python.
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > _MAX_BUILD_ENTRIES:
                            _reject("capability_build_oversized")
                        if entry.is_symlink() or getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0) & 0x400:
                            _reject("capability_path_unsafe")
                        if entry.is_dir(follow_symlinks=False):
                            if entry.name != "__pycache__":
                                pending.append((Path(entry.path), depth + 1))
                        elif entry.name.endswith(".py"):
                            paths.append(Path(entry.path))
                        if len(paths) > _MAX_BUILD_FILES:
                            _reject("capability_build_oversized")
        paths.extend(extras)
        if not paths or len(paths) > _MAX_BUILD_FILES:
            _reject("capability_build_missing")
        self._inventories[key] = (tuple(sorted(paths)), directories)
        return self._hash_paths(paths)

    def _hash_paths(self, paths):
        records, total = [], 0
        for path in sorted(paths):
            before = _fingerprint(path)
            total += before[2]
            if total > _MAX_BUILD_BYTES:
                _reject("capability_build_oversized")
            cached = self._cache.get(path)
            if cached is None or cached[0] != before:
                payload, observed = _read(path, _MAX_BUILD_BYTES)
                cached = self._cache[path] = (observed, _sha(payload))
            records.append(path.relative_to(_ROOT).as_posix() + "\0" + cached[1] + "\n")
        return _sha("".join(records).encode("utf-8"))

    def __call__(self):
        return BuildIdentity(
            self._inventory((_ROOT / "sentinel",), (_ROOT / "scripts" / "invoke-sentinel.ps1",)),
            self._inventory((_ROOT / "tests" / "windows", _ROOT / "tests" / "benchmarks", _ROOT / "tests" / "fixtures")),
        )


@dataclass(frozen=True)
class LiveCapabilityContext:
    host_id_sha256: str
    os_major: int
    os_minor: int
    os_build: int
    logical_processors: int
    processor_groups: int
    process_affinity: str
    logon_id: str
    session_id: int
    session_protocol: int
    python_version: str
    python_bits: int
    python_sha256: str
    parent_job: bool
    shell_hosts_sha256: str

    def __post_init__(self):
        if not all(_digest(value) for value in (self.host_id_sha256, self.python_sha256, self.shell_hosts_sha256)):
            _reject("capability_context_invalid")
        for value in (self.os_major, self.os_minor, self.os_build, self.session_id):
            _integer(value)
        _integer(self.logical_processors, minimum=1, maximum=64)
        if (type(self.processor_groups) is not int or self.processor_groups != 1 or
                type(self.python_bits) is not int or self.python_bits != 64 or
                type(self.session_protocol) is not int or self.session_protocol not in {0, 2} or
                type(self.parent_job) is not bool or self.parent_job):
            _reject("capability_context_unsupported")
        if (type(self.process_affinity) is not str or not re.fullmatch(r"[0-9]{1,20}", self.process_affinity) or
                int(self.process_affinity).bit_count() != self.logical_processors or
                type(self.logon_id) is not str or not re.fullmatch(r"S-1-5-5-[0-9]{1,10}-[0-9]{1,10}", self.logon_id) or
                type(self.python_version) is not str or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", self.python_version)):
            _reject("capability_context_invalid")

    @property
    def fingerprint(self):
        import json
        return _sha(json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8"))


class NativeContextSource:
    """Current native context, including session protocol; RDP is not banned.

    Microsoft WTS_INFO_CLASS WTSClientProtocolType is USHORT 0=console/2=RDP:
    https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/ne-wtsapi32-wts_info_class
    WTSQuerySessionInformationW buffers must be released by WTSFreeMemory.
    This scope fingerprint is not by itself evidence of CPU-rate support.
    """
    def __init__(self):
        self._binary = None
        self._pending_buffer = None
        self._current = None
        self._failure = None
        self._shell_cache = {}

    def _shell_digest(self):
        paths = {"powershell51": Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"}
        pwsh = shutil.which("pwsh.exe")
        if pwsh is not None:
            paths["pwsh"] = Path(pwsh)
        records = []
        for name, path in sorted(paths.items()):
            _safe_directory(path.parent)
            stamp = _fingerprint(path)
            if self._shell_cache.get(path, (None,))[0] != stamp:
                data, checked = _read(path, _MAX_BUILD_BYTES)
                self._shell_cache[path] = (checked, _sha(data))
            records.append(name + "\0" + self._shell_cache[path][1] + "\n")
        return _sha("".join(records).encode("utf-8"))

    def __call__(self):
        if self._pending_buffer is not None or self._failure is not None:
            _reject("capability_context_cleanup_unknown")
        host = read_host_capability()
        try:
            self._current = current = VerifiedProcess.current()
            observed = current.observe()
            if observed.status is not IdentityStatus.ALIVE or observed.identity != current.identity or host.pid != current.identity.pid:
                _reject("capability_context_identity_unknown")
            logon = current.identity.logon_id
            current.close()
            self._current = None
        except BaseException as error:
            # Retain the exact owner/constructor exception. Never reacquire or
            # reclose after an ambiguous native outcome to obtain eligibility.
            self._failure = error
            raise
        kernel, wts = C.WinDLL("kernel32", use_last_error=True), C.WinDLL("wtsapi32", use_last_error=True)
        kernel.ProcessIdToSessionId.argtypes = (C.c_uint32, C.POINTER(C.c_uint32))
        kernel.ProcessIdToSessionId.restype = C.c_int
        wts.WTSQuerySessionInformationW.argtypes = (C.c_void_p, C.c_uint32, C.c_int, C.POINTER(C.c_void_p), C.POINTER(C.c_uint32))
        wts.WTSQuerySessionInformationW.restype = C.c_int
        wts.WTSFreeMemory.argtypes, wts.WTSFreeMemory.restype = (C.c_void_p,), None
        session, size, pointer = C.c_uint32(), C.c_uint32(), C.c_void_p()
        if not kernel.ProcessIdToSessionId(host.pid, C.byref(session)):
            _reject("capability_context_session_unknown")
        known_allocation = False
        try:
            self._pending_buffer = (wts, pointer)
            result = wts.WTSQuerySessionInformationW(None, session.value, 16, C.byref(pointer), C.byref(size))
            if not result:
                if not pointer.value:
                    self._pending_buffer = None
                _reject("capability_context_protocol_unknown")
            known_allocation = True
            if not pointer.value or size.value != C.sizeof(C.c_ushort):
                _reject("capability_context_protocol_unknown")
            protocol = C.cast(pointer, C.POINTER(C.c_ushort)).contents.value
        finally:
            if known_allocation and pointer.value:
                wts.WTSFreeMemory(pointer)
                self._pending_buffer = None
        executable = Path(sys._base_executable)
        before = _fingerprint(executable)
        if self._binary is None or self._binary[0] != before:
            data, checked = _read(executable, _MAX_BUILD_BYTES)
            self._binary = (checked, _sha(data))
        return LiveCapabilityContext(_sha(local_host_identity().encode("utf-8")), host.os_major, host.os_minor,
            host.os_build, host.logical_processors, host.processor_groups, host.process_affinity, logon,
            session.value, protocol, ".".join(str(v) for v in sys.version_info[:3]), C.sizeof(C.c_void_p) * 8,
            self._binary[1], False, self._shell_digest())


@dataclass(frozen=True)
class VerifiedCapability:
    logical_processors: int
    config_revision: str
    bundle_sha256: str
    purpose: str
    host_fingerprint: str


@dataclass(frozen=True)
class VerifiedLaunchScope:
    """Cached native provenance from a trusted in-process collaborator.

    This typed receipt is an integration seam, not a serialized permission.
    The collaborator must independently validate the pinned S2 measurement
    against retained actual wrapper/console/stdio provenance, then return a
    receipt for this exact execution and capability binding. It must prepare
    outside POLICY/Job locks; its callable here may only consult retained
    memory, never probe processes/files or parse new evidence under the lock.
    """
    execution_id: str
    config_revision: str
    host_fingerprint: str
    bundle_sha256: str
    measured_topology_sha256: str
    actual_topology_sha256: str

    def __post_init__(self):
        _uuid(self.execution_id)
        if not all(_digest(value) for value in (self.config_revision,
                self.host_fingerprint, self.bundle_sha256,
                self.measured_topology_sha256, self.actual_topology_sha256)):
            _reject("capability_launch_scope_unverified")


@dataclass(frozen=True)
class CapabilityAssessment:
    eligible: bool
    reason: str
    missing_gates: tuple[str, ...] = ()
    failed_gates: tuple[str, ...] = ()
    verified: VerifiedCapability | None = None
    scope_notes: tuple[str, ...] = ()


def _cleanup(value):
    _object(value, ("cpu_flags", "active_processes", "pending_intents", "unsettled_handles", "live_allocations"))
    for number in value.values():
        if _integer(number) != 0:
            _reject("capability_cleanup_unverified")


def _cpu(value, *, rate=None):
    _object(value, ("flags", "rate_bp"))
    flags, observed = _integer(value["flags"]), _integer(value["rate_bp"], maximum=10000)
    if (rate is None and flags != 0) or (rate is not None and (flags != 5 or observed != rate)):
        _reject("capability_cpu_readback_failed")


def _window(value):
    _object(value, ("start_ns", "end_ns", "cpu_start_100ns", "cpu_end_100ns", "members_start", "members_end"))
    for number in value.values():
        _integer(number)
    elapsed = (value["end_ns"] - value["start_ns"]) / 1e9
    cpu = (value["cpu_end_100ns"] - value["cpu_start_100ns"]) / _TICKS
    if elapsed < 30 or cpu < 0 or value["members_start"] < 1 or value["members_start"] != value["members_end"]:
        _reject("capability_cpu_window_invalid")
    return cpu / elapsed


def _s1(data, context):
    _object(data, ("prerequisites", "rounds"))
    prerequisites = _object(data["prerequisites"], ("self_stop_elapsed_ns", "self_stop_exit_code", "empty_restore", "foreign_parent_jobs", "foreign_parent_launches"))
    if not 0 < _integer(prerequisites["self_stop_elapsed_ns"]) <= 120 * 1e9 or _integer(prerequisites["self_stop_exit_code"]) != 0:
        _reject("capability_self_stop_failed")
    _cleanup(prerequisites["empty_restore"])
    if _integer(prerequisites["foreign_parent_jobs"]) < 1 or _integer(prerequisites["foreign_parent_launches"]) != 0:
        _reject("capability_foreign_parent_rejection_failed")
    rounds = _list(data["rounds"], minimum=10, maximum=10)
    seen, nonces = set(), set()
    for row in rounds:
        _object(row, ("iteration", "nonce", "denominator", "rate_bp", "worker_count", "initial", "applied", "reopened", "restored", "uncapped_window", "capped_window", "restored_window", "containment", "cleanup"))
        index = _integer(row["iteration"], maximum=9)
        if index in seen or not re.fullmatch(r"[0-9a-f]{32}", row["nonce"] if type(row["nonce"]) is str else "") or row["nonce"] in nonces:
            _reject("capability_case_identity_invalid")
        seen.add(index)
        nonces.add(row["nonce"])
        if _integer(row["denominator"]) != context.logical_processors or _integer(row["rate_bp"]) != 2500:
            _reject("capability_denominator_mismatch")
        workers = _integer(row["worker_count"], minimum=1, maximum=context.logical_processors)
        contained = _object(row["containment"], ("before_user_code_members", "extended_limit_flags", "ui_restrictions", "reopened_nonce", "allowed_logon_id", "protected_dacl", "allow_ace_count", "infra_in_work_job"))
        if (_integer(contained["before_user_code_members"]) != workers or
                contained["reopened_nonce"] != row["nonce"] or contained["allowed_logon_id"] != context.logon_id or
                _integer(contained["protected_dacl"]) != 1 or _integer(contained["allow_ace_count"]) != 1):
            _reject("capability_containment_unverified")
        _zero_observations(contained, ("extended_limit_flags", "ui_restrictions", "infra_in_work_job"))
        _cpu(row["initial"])
        _cpu(row["applied"], rate=2500)
        _cpu(row["reopened"], rate=2500)
        _cpu(row["restored"])
        baseline, applied, restored = (_window(row[name]) for name in ("uncapped_window", "capped_window", "restored_window"))
        windows = [row[name] for name in ("uncapped_window", "capped_window", "restored_window")]
        if any(left["end_ns"] > right["start_ns"] for left, right in zip(windows, windows[1:])) or any(value > context.logical_processors for value in (baseline, applied, restored)):
            _reject("capability_cpu_window_invalid")
        target, tolerance = context.logical_processors * .25, max(.15, context.logical_processors * .025)
        if baseline < workers * .9 or baseline < target + tolerance + .25:
            _reject("capability_canary_not_saturated")
        if abs(applied - target) > tolerance or restored < baseline * .9 or restored < target + tolerance + .25:
            _reject("capability_cpu_effect_failed")
        for name in ("uncapped_window", "capped_window", "restored_window"):
            if row[name]["members_start"] != workers:
                _reject("capability_membership_unverified")
        _cleanup(row["cleanup"])


def _zero_observations(observations, names):
    for name in names:
        if name not in observations or _integer(observations[name]) != 0:
            _reject("capability_safety_invariant_failed")


def _cases(data, matrix, *, recovery, require_complete=True):
    _object(data, ("cases",))
    seen = set()
    for row in _list(data["cases"], maximum=512):
        _object(row, ("case", "iteration", "observations", "cleanup"))
        case = row["case"]
        if case not in matrix:
            _reject("capability_case_unknown")
        iteration = _integer(row["iteration"], minimum=1, maximum=matrix[case])
        if (case, iteration) in seen:
            _reject("capability_case_duplicate")
        seen.add((case, iteration))
        values = row["observations"]
        common = ("started_tick", "ended_tick", "wrong_pid_mutations", "workload_kills", "premature_releases")
        extra = (("fault_tick", "fault_observed_tick", "disabled_query_tick", "disabled_flags", "remaining_members_before_stop", "writer_overlap_count", "slot_owner_count", "fault_observations", "scope_nonce") if recovery else
                 ("expected_exit_code", "observed_exit_code", "expected_output_sha256", "observed_output_sha256", "expected_launches", "observed_launches", "membership_mismatches", "root_exit_tick", "last_child_exit_tick", "live_child_count_after_root", "collector_fixture_exit_tick", "guardian_alive_after_collector_tick", "infra_exit_code"))
        _object(values, (*common, *extra))
        start, end = _integer(values["started_tick"]), _integer(values["ended_tick"])
        if end <= start or (recovery and end - start > 120 * _TICKS):
            _reject("capability_case_deadline_failed")
        _zero_observations(values, ("wrong_pid_mutations", "workload_kills", "premature_releases"))
        if recovery:
            query = _integer(values["disabled_query_tick"])
            fault, observed = _integer(values["fault_tick"]), _integer(values["fault_observed_tick"])
            if not start < fault <= observed < query <= end or _integer(values["disabled_flags"]) != 0:
                _reject("capability_restore_unverified")
            _integer(values["remaining_members_before_stop"], minimum=1)
            _integer(values["slot_owner_count"], maximum=1)
            _integer(values["fault_observations"], minimum=1)
            if type(values["scope_nonce"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", values["scope_nonce"]):
                _reject("capability_case_identity_invalid")
            _zero_observations(values, ("writer_overlap_count",))
        else:
            for name in ("expected_exit_code", "observed_exit_code", "expected_launches", "observed_launches"):
                _integer(values[name])
            if (values["expected_exit_code"] != values["observed_exit_code"] or
                    values["expected_launches"] != values["observed_launches"] or
                    not _digest(values["expected_output_sha256"]) or values["expected_output_sha256"] != values["observed_output_sha256"]):
                _reject("capability_launch_semantics_failed")
            _integer(values["observed_launches"], minimum=0 if case == "infra_exit_125" else 1)
            expected_exit = {"exit_0": 0, "exit_7": 7, "child_exit_125": 125, "infra_exit_125": 125}.get(case)
            if expected_exit is not None and values["observed_exit_code"] != expected_exit:
                _reject("capability_launch_semantics_failed")
            _integer(values["infra_exit_code"])
            if (case == "infra_exit_125" and (values["observed_launches"] != 0 or values["infra_exit_code"] != 125)) or (case != "infra_exit_125" and values["infra_exit_code"] != 0):
                _reject("capability_launch_semantics_failed")
            for name in ("root_exit_tick", "last_child_exit_tick", "live_child_count_after_root", "collector_fixture_exit_tick", "guardian_alive_after_collector_tick"):
                _integer(values[name])
            if case == "root_child_survival" and not (start < values["root_exit_tick"] < values["last_child_exit_tick"] <= end and values["live_child_count_after_root"] >= 1):
                _reject("capability_child_survival_unverified")
            if case == "collector_isolation" and not start < values["collector_fixture_exit_tick"] < values["guardian_alive_after_collector_tick"] <= end:
                _reject("capability_collector_isolation_unverified")
            _zero_observations(values, ("membership_mismatches",))
        _cleanup(row["cleanup"])
    if require_complete and seen != {(case, iteration) for case, count in matrix.items() for iteration in range(1, count + 1)}:
        _reject("capability_case_matrix_incomplete")


def _s2(data, context):
    from .launch_topology import LaunchTopology
    _object(data, ("hosts",))
    records, seen, eligible = [], set(), []
    for host in _list(data["hosts"], maximum=2):
        _object(host, ("name", "executable_sha256", "measured_topologies", "cases"))
        name = host["name"]
        if name not in {"powershell51", "pwsh"} or name in seen or not _digest(host["executable_sha256"]):
            _reject("capability_shell_scope_invalid")
        seen.add(name)
        records.append(name + "\0" + host["executable_sha256"] + "\n")
        topologies = {}
        for value in _list(host["measured_topologies"], maximum=16):
            try:
                topology = LaunchTopology.from_dict(value)
            except Exception:
                _reject("capability_launch_topology_invalid")
            if (topology.shell_kind != name or topology.shell_image_sha256 != host["executable_sha256"] or
                    topology.python_image_sha256 != context.python_sha256 or topology.sha256 in topologies):
                _reject("capability_launch_topology_mismatch")
            topologies[topology.sha256] = topology
        referenced, groups, infrastructure = set(), {}, []
        for row in _list(host["cases"], maximum=512):
            _object(row, ("case", "iteration", "observations", "cleanup", "topology_sha256"))
            if row["case"] == "infra_exit_125":
                if row["topology_sha256"] is not None:
                    _reject("capability_unlaunched_topology_claim")
                infrastructure.append({key: value for key, value in row.items() if key != "topology_sha256"})
            else:
                digest = row["topology_sha256"]
                if not _digest(digest) or digest not in topologies:
                    _reject("capability_launch_topology_unmeasured")
                referenced.add(digest)
                groups.setdefault(digest, []).append({key: value for key, value in row.items() if key != "topology_sha256"})
        if referenced != set(topologies):
            _reject("capability_launch_topology_unmeasured")
        complete = {(case, iteration) for case, count in S2_CASES.items()
                    for iteration in range(1, count + 1)}
        promoted = []
        for digest, cases in groups.items():
            matrix = cases + infrastructure
            # Even an observed-only variant must contain valid observations,
            # no duplicates, no unsafe outcomes, and valid cleanup. It cannot
            # borrow missing launch cases from a different topology.
            _cases({"cases": matrix}, S2_CASES, recovery=False, require_complete=False)
            covered = {(row["case"], row["iteration"]) for row in matrix}
            if covered == complete:
                promoted.append(topologies[digest])
        if not promoted:
            _reject("capability_topology_case_matrix_incomplete")
        eligible.extend(promoted)
    if "powershell51" not in seen or _sha("".join(sorted(records)).encode("utf-8")) != context.shell_hosts_sha256:
        _reject("capability_shell_scope_mismatch")
    return tuple(eligible)


def _p95(values):
    ordered = sorted(_finite(value) for value in _list(values))
    return ordered[math.ceil(.95 * len(ordered)) - 1]


def _p4_telemetry(value, context, *, roles=None, nonce=None, reports=None, helper_instance=None):
    """Recompute bounded receipt coverage and exact per-file conservation.

    This is observational evidence, never a source of accounting/control rights.
    Fresh isolated stores must have an empty chunk inventory before the first
    real append. The lock's one byte is explicitly included throughout. Native
    rotation/age/storage-fault recovery proof remains a separate acceptance gap;
    this verifier does not relax the existing idle-after log comparison.
    """
    cap, age, chunk_cap = 20 * 1024 * 1024, 7 * 24 * 60 * 60 * 1_000_000_000, 512 * 1024
    _object(value, ("schema_version", "scope_nonce", "max_bytes", "max_age_ns",
                    "lock_identity", "final_inventory", "sinks"))
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["max_bytes"]) is not int or value["max_bytes"] != cap
            or type(value["max_age_ns"]) is not int or value["max_age_ns"] != age
            or type(value["scope_nonce"]) is not str
            or re.fullmatch(r"[0-9a-f]{32}", value["scope_nonce"]) is None
            or nonce is not None and value["scope_nonce"] != nonce):
        _reject("capability_telemetry_binding_invalid")

    def file_id(item):
        # Native filesystem identities are not signed performance counters.
        # Windows can expose unsigned/128-bit file indices (e.g. ReFS).
        # Keep this bound local; CPU/time/byte measurements retain their limits.
        device, inode = _list(item, minimum=2, maximum=2)
        return (_integer(device, minimum=1, maximum=(1 << 64) - 1),
                _integer(inode, minimum=1, maximum=(1 << 128) - 1))

    lock = file_id(value["lock_identity"])

    def inventory(items):
        result, identities = {}, set()
        for item in _list(items, minimum=0, maximum=63):
            _list(item, minimum=5, maximum=5)
            name, size, created, kind, identity = item
            if type(name) is not str or (match := re.fullmatch(
                    r"(aggregate|event)-([0-9]{20})-([0-9a-f]{32})\.jsonl", name)) is None:
                _reject("capability_telemetry_inventory_invalid")
            identity = file_id(identity)
            size, created = _integer(size, minimum=1), _integer(created)
            if (name in result or identity in identities or identity == lock or size > chunk_cap
                    or kind != match[1] or created != int(match[2])):
                _reject("capability_telemetry_inventory_invalid")
            identities.add(identity)
            result[name] = (size, created, kind, identity)
        if 1 + sum(item[0] for item in result.values()) > cap:
            _reject("capability_telemetry_quota_exceeded")
        return result

    final = inventory(value["final_inventory"])
    all_writes, seen, identities = [], set(), set()
    helper_offers, helper_persisted = {}, set()
    expected_status = ("role", "instance_id", "offered", "accepted", "persisted", "dropped",
        "coalesced", "pending_records", "written_bytes", "deleted_bytes", "inventory_bytes",
        "rotations", "error", "stopping", "stopped", "retained_files", "max_bytes", "max_age_ns")
    for sink in _list(value["sinks"], minimum=3, maximum=3):
        _object(sink, ("role", "identity", "instance_id", "status", "offers", "writes"))
        role = sink["role"]
        try:
            identity = ProcessIdentity.from_dict(sink["identity"])
        except Exception:
            _reject("capability_telemetry_binding_invalid")
        if (type(role) is not str or role not in {"helper", "guardian", "supervisor"} or role in seen
                or identity in identities or identity.logon_id != context.logon_id
                or roles is not None and identity != roles[role][0]):
            _reject("capability_telemetry_binding_invalid")
        seen.add(role)
        identities.add(identity)
        _uuid(sink["instance_id"])
        if role == "helper" and helper_instance is not None and sink["instance_id"] != helper_instance:
            _reject("capability_telemetry_binding_invalid")
        status = _object(sink["status"], expected_status)
        if (status["role"] != role or status["instance_id"] != sink["instance_id"]
                or status["error"] is not None or status["stopping"] is not False
                or status["stopped"] is not False or status["max_bytes"] != cap
                or status["max_age_ns"] != age):
            _reject("capability_telemetry_degraded")
        numeric = set(expected_status) - {"role", "instance_id", "error", "stopping", "stopped"}
        for key in numeric:
            _integer(status[key])
        if status["dropped"] or status["pending_records"] > 128 or status["retained_files"] > 2:
            _reject("capability_telemetry_degraded")
        offers, superseded = {}, set()
        for index, item in enumerate(_list(sink["offers"], maximum=16000), 1):
            _list(item, minimum=4, maximum=4)
            sequence, size, kind, prior = item
            _integer(sequence, minimum=1)
            _integer(size, minimum=1)
            if sequence != index or size > 16 * 1024 or kind not in ("event", "aggregate"):
                _reject("capability_telemetry_offer_coverage_invalid")
            if prior is not None:
                _integer(prior, minimum=1)
                if kind != "aggregate" or prior not in offers or offers[prior][1] != "aggregate" or prior in superseded:
                    _reject("capability_telemetry_coalescing_invalid")
                superseded.add(prior)
            offers[sequence] = (size, kind)
        persisted, written, deleted, rotations, utc = set(), 0, 0, 0, -1
        last_bytes = 0
        for index, write in enumerate(_list(sink["writes"], maximum=2048), 1):
            _object(write, ("sequence", "offers", "before", "after", "deleted", "utc_ns", "lock_identity", "kind"))
            if _integer(write["sequence"], minimum=1) != index or file_id(write["lock_identity"]) != lock:
                _reject("capability_telemetry_write_coverage_invalid")
            now = _integer(write["utc_ns"])
            if now < utc or write["kind"] not in ("event", "aggregate"):
                _reject("capability_telemetry_clock_invalid")
            utc = now
            byte_count = 0
            for item in _list(write["offers"], maximum=128):
                _list(item, minimum=2, maximum=2)
                seq, size = (_integer(v, minimum=1) for v in item)
                if (seq not in offers or offers[seq] != (size, write["kind"])
                        or seq in persisted or seq in superseded):
                    _reject("capability_telemetry_persistence_invalid")
                persisted.add(seq)
                byte_count += size
            if byte_count > 64 * 1024:
                _reject("capability_telemetry_write_bound")
            before, after, removed = (inventory(write[name]) for name in ("before", "after", "deleted"))
            if any(name not in before or before[name] != item for name, item in removed.items()):
                _reject("capability_telemetry_file_conservation_failed")
            survivors = {name: item for name, item in before.items() if name not in removed}
            if any(name not in after for name in survivors):
                _reject("capability_telemetry_file_conservation_failed")
            changes = []
            for name, item in after.items():
                old = survivors.get(name)
                if old is None:
                    if name in before or item[0] != byte_count or item[1] != now or item[2] != write["kind"]:
                        _reject("capability_telemetry_file_conservation_failed")
                    changes.append(name)
                elif item != old:
                    if item[1:] != old[1:] or item[0] - old[0] != byte_count or item[2] != write["kind"]:
                        _reject("capability_telemetry_file_conservation_failed")
                    changes.append(name)
            if (len(changes) != 1 or any(item[1] > now or item[1] < now - age for item in after.values())
                    or 1 + sum(item[0] for item in survivors.values()) + byte_count > cap):
                _reject("capability_telemetry_file_conservation_failed")
            removed_bytes = sum(item[0] for item in removed.values())
            written += byte_count
            deleted += removed_bytes
            rotations += len(removed)
            last_bytes = 1 + sum(item[0] for item in after.values())
            all_writes.append((before, after, now))
        if (status["offered"] != len(offers) or status["accepted"] != len(offers)
                or status["persisted"] != len(persisted) or status["coalesced"] != len(superseded)
                or status["pending_records"] != len(set(offers) - persisted - superseded)
                or status["written_bytes"] != written or status["deleted_bytes"] != deleted
                or status["rotations"] != rotations or status["inventory_bytes"] != last_bytes):
            _reject("capability_telemetry_counter_mismatch")
        if role == "helper":
            helper_offers, helper_persisted = offers, persisted
    # Independent role-local counters do not order shared writes. Reconstruct
    # the unique complete native inventory chain, including every other writer.
    current, utc = {}, -1
    while all_writes:
        matches = [index for index, row in enumerate(all_writes) if row[0] == current]
        if len(matches) != 1:
            _reject("capability_telemetry_shared_write_coverage_incomplete")
        _, current, now = all_writes.pop(matches[0])
        if now < utc:
            _reject("capability_telemetry_clock_invalid")
        utc = now
    if current != final:
        _reject("capability_telemetry_final_inventory_mismatch")
    if reports is None:
        reports = [(seq, size) for seq, (size, kind) in helper_offers.items() if kind == "aggregate"]
    for sequence, size in reports:
        if sequence not in helper_persisted or helper_offers.get(sequence) != (size, "aggregate"):
            _reject("capability_telemetry_report_not_persisted")
    return 1 + sum(item[0] for item in final.values())


def _p4(data, context, profile):
    _object(data, ("schema_version", "scales", "wrapper_cold_ns", "wrapper_warm_ns", "wrapper_telemetry", "leak"))
    if type(data["schema_version"]) is not int or data["schema_version"] != 2:
        _reject("capability_p4_schema_unsupported")
    seen, notes = set(), []
    for row in _list(data["scales"], minimum=3, maximum=3):
        _object(row, ("jobs", "started_tick", "ended_tick", "processes", "samples", "native_set_calls", "sampling_cases", "host_loop", "telemetry"))
        jobs = _integer(row["jobs"])
        if jobs not in {1, 10, 50} or jobs in seen:
            _reject("capability_cost_scope_invalid")
        seen.add(jobs)
        start, end = _integer(row["started_tick"]), _integer(row["ended_tick"])
        elapsed = end - start
        if elapsed < 600 * _TICKS:
            _reject("capability_cost_duration_missing")
        observer_roles = {"supervisor", "accounting_keeper", "daily_activation"}
        role_members = {name: [] for name in observer_roles | {"helper", "guardian", "waiting_wrapper"}}
        identities, pids, process_roles, delta = set(), set(), [], 0
        processes = _list(row["processes"], minimum=1, maximum=55)
        for process in processes:
            _object(process, ("identity", "roles", "cpu_start_100ns", "cpu_end_100ns"))
            try:
                identity = ProcessIdentity.from_dict(process["identity"])
            except Exception:
                _reject("capability_monitor_identity_invalid")
            roles = _list(process["roles"], maximum=len(role_members))
            if (any(type(role) is not str or role not in role_members for role in roles)
                    or roles != sorted(set(roles))
                    or (len(roles) > 1 and not set(roles) <= observer_roles)
                    or identity in identities or identity.pid in pids
                    or identity.logon_id != context.logon_id):
                _reject("capability_monitor_identity_invalid")
            identities.add(identity)
            pids.add(identity.pid)
            process_roles.append(set(roles))
            for role in roles:
                role_members[role].append(identity)
            used = _integer(process["cpu_end_100ns"]) - _integer(process["cpu_start_100ns"])
            if not 0 <= used <= elapsed * context.logical_processors:
                _reject("capability_cost_counter_invalid")
            delta += used
        if any(len(members) != (jobs if role == "waiting_wrapper" else 1)
               for role, members in role_members.items()):
            _reject("capability_monitor_coverage_incomplete")
        ticks, private_values, wrapper_values, previous, previous_end = [], [], [], start, start
        samples = _list(row["samples"], minimum=2)
        for sample in samples:
            # Native peaks are in unique process-row order. Derive all buckets
            # here so aliased infrastructure roles cannot be counted twice or
            # extra resident observers disappear behind the original H+G total.
            _list(sample, minimum=7, maximum=7)
            begin, finish, helper_guardian, wrapper_bytes, resident, total = (
                _integer(v) for v in sample[:6])
            peaks = [_integer(value) for value in _list(sample[6],
                minimum=len(processes), maximum=len(processes))]
            expected_helper_guardian = sum(value for value, roles in zip(peaks, process_roles)
                if roles & {"helper", "guardian"})
            expected_wrappers = max(value for value, roles in zip(peaks, process_roles)
                if "waiting_wrapper" in roles)
            expected_resident = sum(value for value, roles in zip(peaks, process_roles)
                if "waiting_wrapper" not in roles)
            if (helper_guardian != expected_helper_guardian or wrapper_bytes != expected_wrappers
                    or resident != expected_resident or total != sum(peaks)):
                _reject("capability_monitor_memory_mismatch")
            if not previous_end <= begin < finish <= end or begin - previous > profile.sample_max_age_ms * 10_000:
                _reject("capability_cost_coverage_incomplete")
            previous, previous_end = begin, finish
            ticks.append((finish - begin) * 100)
            # Charge all resident observers to the unchanged 160 MiB budget;
            # newly introduced infrastructure gets no separate allowance.
            private_values.append(resident)
            wrapper_values.append(wrapper_bytes)
        if end - previous > profile.sample_max_age_ms * 10_000:
            _reject("capability_cost_coverage_incomplete")
        host = _object(row["host_loop"], ("identity", "parent_identity", "instance_id",
            "operator_instance_id", "scope_nonce", "config_revision", "managed_execution_ids",
            "query_only_execution_ids", "enroll_every_ticks", "report_every_ticks",
            "started_iteration", "ended_iteration", "telemetry_instance_id", "ticks"))
        try:
            helper_identity = ProcessIdentity.from_dict(host["identity"])
            parent_identity = ProcessIdentity.from_dict(host["parent_identity"])
        except Exception:
            _reject("capability_host_loop_binding_invalid")
        for name in ("instance_id", "operator_instance_id"):
            _uuid(host[name])
        if (helper_identity != role_members["helper"][0]
                or parent_identity != role_members["supervisor"][0]
                or host["instance_id"] == host["operator_instance_id"]
                or type(host["scope_nonce"]) is not str
                or re.fullmatch(r"[0-9a-f]{32}", host["scope_nonce"]) is None
                or host["config_revision"] != profile_revision(profile)):
            _reject("capability_host_loop_binding_invalid")
        managed_count = min(jobs, 10)
        managed = _list(host["managed_execution_ids"], minimum=managed_count, maximum=managed_count)
        query_only = _list(host["query_only_execution_ids"],
            minimum=jobs - managed_count, maximum=jobs - managed_count)
        for execution_id in (*managed, *query_only):
            _uuid(execution_id)
        if (len(set((*managed, *query_only))) != jobs
                or managed_count > profile.max_enrolled_jobs or profile.max_enrolled_jobs > 10):
            _reject("capability_host_loop_scope_invalid")
        enroll_every = _integer(host["enroll_every_ticks"], minimum=1, maximum=3600)
        report_every = _integer(host["report_every_ticks"], minimum=1, maximum=3600)
        if report_every != 30:
            _reject("capability_host_loop_cadence_changed")
        first_iteration, last_iteration = (_integer(host[name])
            for name in ("started_iteration", "ended_iteration"))
        host_ticks = _list(host["ticks"], minimum=len(samples), maximum=len(samples))
        if last_iteration - first_iteration != len(samples):
            _reject("capability_host_loop_coverage_incomplete")
        refreshes = reports = 0
        report_receipts = []
        for index, (sample, observation) in enumerate(zip(samples, host_ticks)):
            _list(observation, minimum=11, maximum=11)
            (iteration, refreshed, reported, operator_polls, report_bytes, deadline,
             wait_started, wait_ended, skipped, overrun, report_sequence) = (_integer(value) for value in observation)
            expected_iteration = first_iteration + index + 1
            expected_refresh = expected_iteration > 1 and (expected_iteration - 1) % enroll_every == 0
            expected_report = expected_iteration % report_every == 0
            if (iteration != expected_iteration or refreshed != int(expected_refresh)
                    or reported != int(expected_report) or operator_polls != 1
                    or (report_bytes > 0) != expected_report or (report_sequence > 0) != expected_report):
                _reject("capability_host_loop_coverage_incomplete")
            next_begin = samples[index + 1][0] if index + 1 < len(samples) else end
            if (deadline <= 0 or wait_started < sample[1] or wait_ended < wait_started
                    or wait_ended < deadline or wait_ended > next_begin
                    or overrun != max(0, wait_started - deadline)):
                _reject("capability_host_loop_pacing_invalid")
            refreshes += refreshed
            reports += reported
            if reported:
                if report_receipts and report_sequence <= report_receipts[-1][0]:
                    _reject("capability_telemetry_report_replayed")
                report_receipts.append((report_sequence, report_bytes))
        if not refreshes or not reports:
            _reject("capability_host_loop_coverage_incomplete")
        _p4_telemetry(row["telemetry"], context, roles=role_members, nonce=host["scope_nonce"],
            reports=report_receipts, helper_instance=host["telemetry_instance_id"])
        cpu, tick = delta / elapsed, _p95(ticks) / 1e9
        private, wrappers = max(private_values), max(wrapper_values)
        _zero_observations(row, ("native_set_calls",))
        cases = _object(row["sampling_cases"], ("membership_added", "membership_removed", "inaccessible_identity", "member_scan_timeout", "subtraction_zero_samples", "unsafe_subtractions"))
        for name in cases:
            _integer(cases[name], minimum=0 if name == "unsafe_subtractions" else 1)
        _zero_observations(cases, ("unsafe_subtractions",))
        # §12.1 S4 explicitly permits a failed 50-Job stress result while
        # retaining the verified <=10-Job scope. Its data must still be valid.
        if jobs <= 10 and (cpu > (.05 if jobs == 1 else .10) or (jobs == 10 and tick > .050) or private > 160 * _MIB or wrappers > 48 * _MIB):
            _reject("capability_observer_budget_failed")
        if jobs == 50:
            stress_failed = cpu > .25 or tick > .100 or private > 160 * _MIB or wrappers > 48 * _MIB
            notes.append("50_job_stress:" + ("failed_outside_allowed_scope" if stress_failed else "measured_within_budget"))
    for name in ("wrapper_cold_ns", "wrapper_warm_ns"):
        if _p95(data[name]) > 500_000_000:
            _reject("capability_wrapper_latency_failed")
    _p4_telemetry(data["wrapper_telemetry"], context)
    leak = _object(data["leak"], ("started_tick", "ended_tick", "idle_before", "idle_after", "observations", "telemetry"))
    leak_start, leak_end = _integer(leak["started_tick"]), _integer(leak["ended_tick"])
    if leak_end - leak_start < 3600 * _TICKS:
        _reject("capability_leak_duration_missing")
    prior_tick = -1
    observations = _list(leak["observations"], minimum=3)
    for observation in observations:
        _list(observation, minimum=5, maximum=5)
        when, *_ = (_integer(v) for v in observation)
        if not leak_start <= when <= leak_end or when <= prior_tick:
            _reject("capability_leak_coverage_incomplete")
        prior_tick = when
    if observations[0][0] != leak_start or observations[-1][0] != leak_end:
        _reject("capability_leak_coverage_incomplete")
    for name in ("idle_before", "idle_after"):
        _object(leak[name], ("private_bytes", "handles", "rows", "log_bytes"))
        for value in leak[name].values():
            _integer(value)
    final_log_bytes = _p4_telemetry(leak["telemetry"], context)
    if (leak["idle_after"]["log_bytes"] != final_log_bytes
            or any(row[4] > 20 * _MIB for row in observations)
            or leak["idle_before"]["log_bytes"] > 20 * _MIB):
        _reject("capability_telemetry_footprint_mismatch")
    # A positive non-growing result is accepted, not a fitted/noisy upward
    # trend reclassified as harmless. Higher post-idle values need additional
    # evidence; this verifier does not invent a permitted leak allowance.
    if any(leak["idle_after"][name] > leak["idle_before"][name] for name in leak["idle_before"]):
        _reject("capability_idle_growth_unresolved")
    return tuple(notes)


def _latencies(rows, fields, *, reaction=False, context=None, profile=None):
    values = []
    seen = set()
    for row in _list(rows, minimum=10):
        _object(row, (*fields, "scope_nonce", "query", *( ("baseline_cpu_units",) if reaction else () )))
        nonce = row["scope_nonce"]
        if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce) or nonce in seen:
            _reject("capability_case_identity_invalid")
        seen.add(nonce)
        ticks = [_integer(row[field]) for field in fields]
        if any(left >= right for left, right in zip(ticks, ticks[1:])):
            _reject("capability_clock_order_invalid")
        if reaction:
            baseline = _finite(row["baseline_cpu_units"], minimum=profile.victim_min_cpu_units)
            if baseline > context.logical_processors:
                _reject("capability_denominator_mismatch")
            expected = math.ceil(10000 * max(profile.cap_floor_cpu_units, baseline * profile.retreat_l1_fraction) / context.logical_processors)
            if not 0 < expected < 10000:
                _reject("capability_cpu_readback_failed")
            _cpu(row["query"], rate=expected)
        else:
            _cpu(row["query"])
        values.append((ticks[-1] - ticks[0]) / _TICKS)
    return values


def _p5(data, context, profile):
    _object(data, ("reaction", "helper_loss", "guardian_loss", "grant_restore", "invariants", "grants"))
    if _p95(_latencies(data["reaction"], ("sample_end", "decision", "apply", "query_confirmed"), reaction=True, context=context, profile=profile)) > 4:
        _reject("capability_reaction_latency_failed")
    for name, first in (("helper_loss", "last_valid_decision"), ("guardian_loss", "guardian_exit_confirmed")):
        if max(_latencies(data[name], (first, "disabled_query"))) > 8:
            _reject("capability_restore_latency_failed")
    if _p95(_latencies(data["grant_restore"], ("grant_commit", "disabled_query"))) > 2:
        _reject("capability_grant_latency_failed")
    _object(data["invariants"], _ZERO_INVARIANTS)
    _zero_observations(data["invariants"], _ZERO_INVARIANTS)
    grants = _object(data["grants"], ("concurrent_attempts", "maximum_live_leases", "deadline_extensions", "early_root_exit_releases"))
    if _integer(grants["concurrent_attempts"]) < 8 or not 1 <= _integer(grants["maximum_live_leases"]) <= 3:
        _reject("capability_atomic_grants_failed")
    _zero_observations(grants, ("deadline_extensions", "early_root_exit_releases"))


_SCENARIOS = ("CPU_CONTENTION", "IO_BOUND", "MEMORY_HEAVY", "NO_PRESSURE",
              "UNMANAGED_CPU_PRESSURE", "MIXED_ROLES", "MIXED_DURATIONS")
_COMPARISONS = ("A0_A1", "A1_B", "A0_B")


def _p6(data):
    """Check the plan's explicit paired arithmetic, without inventing policy.

    Item 6 must still define/promote the measured-noise estimator, the A0
    clarifications and reserve-loss attribution before LIMITED can be granted.
    This validates all named scenario/comparison data, never labels a partial
    A1/B-only comparison as complete promotion evidence.
    """
    _object(data, ("order_seed", "fixed_conditions_sha256", "pairs"))
    seed = _integer(data["order_seed"])
    if not _digest(data["fixed_conditions_sha256"]):
        _reject("capability_ab_conditions_invalid")
    groups, seen = {}, set()
    fields = ("foreground_p95_ms", "makespan_s", "throughput_units_min", "queue_wait_p95_ms")
    for pair in _list(data["pairs"], minimum=210, maximum=2100):
        _object(pair, ("scenario", "comparison", "pair_index", "order", "fixed_conditions_sha256", "baseline", "candidate", "unrelated_caps", "new_admission_reserve_losses", "api_errors", "unrestored_caps"))
        scenario, comparison = pair["scenario"], pair["comparison"]
        if scenario not in _SCENARIOS or comparison not in _COMPARISONS:
            _reject("capability_ab_scope_invalid")
        index = _integer(pair["pair_index"], maximum=99)
        key = (scenario, comparison, index)
        if key in seen or pair["order"] != ("AB" if (index + seed) % 2 == 0 else "BA") or pair["fixed_conditions_sha256"] != data["fixed_conditions_sha256"]:
            _reject("capability_ab_pair_binding_invalid")
        seen.add(key)
        for side in ("baseline", "candidate"):
            _object(pair[side], fields)
            for name in fields:
                number = _finite(pair[side][name])
                if name != "queue_wait_p95_ms" and number <= 0:
                    _reject("capability_ab_measurement_invalid")
        _zero_observations(pair, ("new_admission_reserve_losses", "api_errors", "unrestored_caps"))
        _integer(pair["unrelated_caps"])
        groups.setdefault((scenario, comparison), []).append(pair)
    expected = {(scenario, comparison) for scenario in _SCENARIOS for comparison in _COMPARISONS}
    if set(groups) != expected or any(len(rows) < 10 for rows in groups.values()):
        _reject("capability_ab_matrix_incomplete")
    for (scenario, comparison), rows in groups.items():
        indices = {row["pair_index"] for row in rows}
        if indices != set(range(len(rows))):
            _reject("capability_ab_matrix_incomplete")
        if comparison != "A1_B":
            continue  # C1/C2 remain explicitly outside this promotion policy.
        def change(metric):
            return statistics.median((r["candidate"][metric] - r["baseline"][metric]) / r["baseline"][metric] for r in rows)
        if scenario == "CPU_CONTENTION":
            if statistics.median(r["baseline"]["foreground_p95_ms"] for r in rows) < 20:
                _reject("capability_ab_no_problem_to_control")
            absolute = statistics.median(r["baseline"]["foreground_p95_ms"] - r["candidate"]["foreground_p95_ms"] for r in rows)
            if change("foreground_p95_ms") > -.15 or absolute < 5 or change("makespan_s") > .15 or change("throughput_units_min") < -.10:
                _reject("capability_ab_cpu_benefit_failed")
        elif scenario in {"IO_BOUND", "MEMORY_HEAVY", "NO_PRESSURE"}:
            if any(r["unrelated_caps"] for r in rows) or change("foreground_p95_ms") > .05 or change("makespan_s") > .05:
                _reject("capability_ab_neutral_regression")
    _reject("p6_promotion_policy_unresolved")


class NativeEvidenceAuthority:
    """Pinned evidence + fresh actual scope; no serialized control permission.

    assess/refresh runs OUTSIDE POLICY and Job locks. Immutable gate data is
    evaluated once; subsequent refreshes check bounded cached source/file
    fingerprints and current host. assert_control_eligible performs only a
    short memory/interrupt-clock check and requires a prepared receipt within
    the profile's existing sample freshness boundary. Callers re-read their
    actuation clock after refresh and before Set. No implicit slow refresh
    occurs inside assertion, and a failed refresh invalidates the old receipt.
    """
    def __init__(self, *, profile, bundle_directory=None, expected_bundle_sha256=None,
                 purpose="isolated_canary", live_context_source=None, build_source=None, clock=None,
                 launch_scope_source=None):
        if not isinstance(profile, PolicyProfile) or purpose not in _PURPOSES:
            _reject("capability_authority_scope_invalid")
        self.profile, self.purpose = profile, purpose
        self.config_revision = profile_revision(profile)
        self.directory = None if bundle_directory is None else Path(bundle_directory)
        self.expected_bundle_sha256 = expected_bundle_sha256
        self.context_source = NativeContextSource() if live_context_source is None else live_context_source
        self.build_source = CurrentBuildSource() if build_source is None else build_source
        self._bundle = None
        self._artifacts = {}
        self._files = {}
        self._failure = None
        self._gates = None
        self._measured_launch_topologies = None
        self._prepared = None
        self._prepared_launch = None
        self._prepared_tick = None
        self._clock_backend = None
        self.clock = self._tick if clock is None else clock
        self.launch_scope_source = launch_scope_source
        self._scope_failure = None

    def _tick(self):
        if self._clock_backend is None:
            from .machine_sampler import _WindowsBackend
            self._clock_backend = _WindowsBackend()
        return self._clock_backend.tick()

    def _load(self):
        if self.directory is None:
            _reject("capability_evidence_missing")
        if not _digest(self.expected_bundle_sha256):
            _reject("capability_evidence_unpinned")
        if not self.directory.is_absolute():
            _reject("capability_path_unsafe")
        _safe_directory(self.directory)
        if self._bundle is not None:
            if any(_fingerprint(path) != value for path, value in self._files.items()):
                _reject("capability_evidence_changed")
            return
        path = self.directory / "bundle.json"
        payload, fingerprint = _read(path, _MAX_BYTES)
        if _sha(payload) != self.expected_bundle_sha256:
            _reject("capability_bundle_hash_mismatch")
        bundle = _object(strict_json_loads(payload), ("schema_version", "kind", "run_id", "evidence_source", "build", "context", "profile_revision", "artifacts"))
        if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1 or bundle["kind"] != "native_capability_bundle":
            _reject("capability_schema_invalid")
        _uuid(bundle["run_id"])
        if bundle["evidence_source"] != "native":
            _reject("capability_evidence_not_native")
        files = {path: fingerprint}
        artifacts = {}
        for reference in _list(bundle["artifacts"], maximum=6):
            _object(reference, ("gate", "path", "sha256"))
            gate, name = reference["gate"], reference["path"]
            if gate not in _PURPOSES["limited"] or gate in artifacts or type(name) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}\.json", name) or name == "bundle.json" or not _digest(reference["sha256"]):
                _reject("capability_artifact_reference_invalid")
            artifact_path = self.directory / name
            raw, checked = _read(artifact_path, _P4_MAX_BYTES if gate == "P4" else _MAX_BYTES)
            if _sha(raw) != reference["sha256"]:
                _reject("capability_artifact_hash_mismatch")
            artifact = _object(_artifact_json_loads(raw, expected_gate=gate), ("schema_version", "run_id", "gate", "evidence_source", "data"))
            if type(artifact["schema_version"]) is not int or artifact["schema_version"] != 1 or artifact["run_id"] != bundle["run_id"] or artifact["gate"] != gate:
                _reject("capability_artifact_binding_invalid")
            if artifact["evidence_source"] != "native":
                _reject("capability_evidence_not_native")
            artifacts[gate] = artifact["data"]
            files[artifact_path] = checked
        self._artifacts, self._bundle, self._files = artifacts, bundle, files

    def assess(self):
        self._prepared, self._prepared_tick = None, None
        self._prepared_launch = None
        missing, failed, notes = [], [], []
        try:
            self._load()
            start = _integer(self.clock())
            context, build = self.context_source(), self.build_source()
            if type(context) is not LiveCapabilityContext or type(build) is not BuildIdentity:
                _reject("capability_live_source_invalid")
            bundle = self._bundle
            if _object(bundle["build"], ("runtime_sha256", "producer_sha256")) != asdict(build):
                _reject("capability_build_mismatch")
            recorded_context = LiveCapabilityContext(**_object(bundle["context"], asdict(context)))
            if recorded_context != context:
                _reject("capability_host_context_mismatch")
            if bundle["profile_revision"] != self.config_revision:
                _reject("capability_profile_mismatch")
            for gate in (() if self._gates is not None else _PURPOSES[self.purpose]):
                if gate not in self._artifacts:
                    missing.append(gate)
                    continue
                try:
                    data = self._artifacts[gate]
                    if gate == "S1":
                        _s1(data, context)
                    elif gate == "S2":
                        self._measured_launch_topologies = _s2(data, context)
                    elif gate == "S3":
                        _cases(data, S3_CASES, recovery=True)
                    elif gate == "P4":
                        notes.extend(_p4(data, context, self.profile))
                    elif gate == "P5":
                        _p5(data, context, self.profile)
                    else:
                        _p6(data)
                except CapabilityEvidenceError as error:
                    failed.append(gate + ":" + error.reason)
            if self._gates is None:
                self._gates = (tuple(missing), tuple(failed), tuple(notes))
            missing, failed, notes = self._gates
            if missing or failed:
                return CapabilityAssessment(False, "capability_required_gates_unverified", missing, failed, scope_notes=notes)
            end = _integer(self.clock())
            if not 0 <= end - start <= self.profile.sample_max_age_ms * 10_000:
                _reject("capability_refresh_stale")
            receipt = VerifiedCapability(context.logical_processors, self.config_revision,
                self.expected_bundle_sha256, self.purpose, context.fingerprint)
            from .launch_scope import MeasuredLaunchTopologies
            self._prepared_launch = MeasuredLaunchTopologies(receipt.config_revision,
                receipt.host_fingerprint, receipt.bundle_sha256, self._measured_launch_topologies)
            self._prepared_tick = start  # age covers the entire live refresh.
            self._prepared = CapabilityAssessment(True, "capability_evidence_verified", verified=receipt, scope_notes=notes)
            return self._prepared
        except CapabilityEvidenceError as error:
            self._failure = error
            return CapabilityAssessment(False, error.reason)
        except Exception as error:
            # Retain possible native/journal cleanup custody privately while
            # returning only an allowlisted reason, not a path or JSON value.
            self._failure = error
            return CapabilityAssessment(False, "capability_evidence_unavailable")

    refresh = assess

    def prepared_launch_topologies(self):
        """Bounded immutable scope read; never load/probe inside a Job fence.

        Each returned topology independently passed the full launched S2 matrix.
        The infrastructure-refusal cases have no launch and are shared. Partial
        secondary observations never acquire another topology's compatibility.
        """
        assessment = self._prepared
        if assessment is None or self._prepared_tick is None or self._prepared_launch is None:
            _reject("capability_receipt_unprepared")
        now = _integer(self.clock())
        if not 0 <= now - self._prepared_tick <= self.profile.sample_max_age_ms * 10_000:
            _reject("capability_receipt_stale")
        return self._prepared_launch

    def assert_proposal_eligible(self, *, profile_revision, logical_processors, execution_row, guardian_identity):
        """Prepared global evidence and row binding for a non-actuating helper.

        This grants no native restriction. Only guardian assert_control_eligible
        additionally proves its original retained launch scope before Set.
        """
        assessment = self._prepared
        if assessment is None or self._prepared_tick is None:
            _reject("capability_receipt_unprepared")
        now = _integer(self.clock())
        if not 0 <= now - self._prepared_tick <= self.profile.sample_max_age_ms * 10_000:
            self._prepared, self._prepared_tick = None, None
            _reject("capability_receipt_stale")
        receipt = assessment.verified
        if (profile_revision != receipt.config_revision or type(logical_processors) is not int or
                logical_processors != receipt.logical_processors):
            _reject("capability_frame_binding_mismatch")
        if not isinstance(execution_row, Mapping) or type(guardian_identity) is not ProcessIdentity:
            _reject("capability_execution_binding_invalid")
        try:
            _uuid(execution_row["execution_id"])
            if (execution_row["role"] != "background" or execution_row["priority"] not in {"P2", "P3"} or
                    execution_row["coverage"] != "job_contained" or execution_row["state"] not in {"RUNNING", "DRAINING"} or
                    type(execution_row["launch_sealed"]) is not int or execution_row["launch_sealed"] != 1 or
                    type(execution_row["launch_in_flight"]) is not int or execution_row["launch_in_flight"] != 0 or
                    not isinstance(execution_row["guardian_epoch"], str) or not execution_row["guardian_epoch"] or
                    execution_row["logon_id"] != guardian_identity.logon_id or
                    guardian_identity.logon_id != self._bundle["context"]["logon_id"]):
                _reject("capability_execution_ineligible")
        except KeyError:
            _reject("capability_execution_binding_invalid")
        return receipt

    def assert_control_eligible(self, *, profile_revision, logical_processors, execution_row, guardian_identity):
        receipt = self.assert_proposal_eligible(profile_revision=profile_revision,
            logical_processors=logical_processors, execution_row=execution_row,
            guardian_identity=guardian_identity)
        if not callable(self.launch_scope_source) or self._scope_failure is not None:
            _reject("capability_launch_scope_unverified")
        binding = dict(execution_id=execution_row["execution_id"],
            config_revision=receipt.config_revision, host_fingerprint=receipt.host_fingerprint,
            bundle_sha256=receipt.bundle_sha256)
        try:
            scope = self.launch_scope_source(**binding)
        except Exception as error:
            from .launch_scope import LaunchScopeUnavailable
            if type(error) is LaunchScopeUnavailable:
                # A known unsupported original topology rejects only this
                # candidate. It does not quarantine other valid executions.
                _reject("capability_launch_scope_unverified")
            # Preserve a collaborator's uncertain custody rather than retrying
            # it or replacing its exception to obtain a positive receipt.
            self._scope_failure = error
            _reject("capability_launch_scope_unverified")
        if (type(scope) is not VerifiedLaunchScope or
                any(getattr(scope, name) != value for name, value in binding.items()) or
                scope.measured_topology_sha256 != scope.actual_topology_sha256):
            _reject("capability_launch_scope_unverified")
        return receipt


class HelperProposalEvidence:
    """Helper-only adapter; the guardian always receives the full authority.

    HelperControl's collaborator method predates separate original-launch
    verification. Adapt only that helper callback; no scope receipt is forged
    and the underlying guardian authority's exact control gate stays intact.
    """
    def __init__(self, authority):
        self.authority = authority

    def assert_control_eligible(self, **binding):
        return self.authority.assert_proposal_eligible(**binding)
