"""Actual serial S1 measurements over original daily/native case custody.

Fixture files are bounded observations, never launch or cleanup authority.
Only the separately attested console may publish this producer's returned data.
This module has no bootstrap, activation, alternate admission or recovery owner.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import math
import os
from pathlib import Path
import stat
import time

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive import daily_generation
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, strict_json_loads
from sentinel.adaptive.experiment_cleanup import ExperimentReleaseOperation
from sentinel.adaptive.experiment_scope import ExperimentNativeScope, NativeScopeCompletion
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import CpuState, JobAccounting, JobLimits, JobSecurity, NativeJob
from tests.windows.adaptive_capability_runner import (
    NativeRunBlocked, NativeRunUnsettled, _write_new, error_evidence,
)
from tests.windows.adaptive_s1_provider import S1Case, S1SerialProvider


WINDOW_NS = 30_000_000_000
ROUNDS = 10
MAX_RECORD_BYTES = 65536
# At most 64 workers each publish one ready and one exit file; retain room
# for the fixed tree/stop/isolated-journal files without an unbounded scan.
MAX_DIRECTORY_ENTRIES = 160
_PINS = {"nonce", "scope_id", "job_name", "source_generation", "source_digest", "fixture_sha256"}
_READY = {"schema_version", "status", "identity", "pid", "created_filetime_100ns", "logon_id",
    "nonce", "job_name", "in_expected_job", "readiness_scope", "role", "parent_pid", "source_generation",
    "source_digest", "fixture_sha256", "deadline_monotonic_ns", "deadline_monotonic",
    "maximum_cpu_work_seconds", "cooperative_cleanup_grace_seconds", "scope_id"}
_TREE = {"schema_version", "status", "root_identity", "child_identities", "deadline_monotonic_ns", *_PINS}
_EXIT = _READY | {"reason", "work_chunks", "elapsed_seconds", "children_still_alive", "owned_handles_closed"}


def _fail(reason):
    raise NativeRunBlocked("native_s1_" + reason)


def _integer(value, *, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("observation_integer_invalid")
    return value


def _cpu(value, *, rate=None):
    if type(value) is not CpuState:
        _fail("cpu_observation_type_invalid")
    _integer(value.flags, maximum=0xffffffff)
    _integer(value.rate_bp, maximum=0xffffffff)
    result = asdict(value)
    if value.flags == 0:
        # The rate is an inactive native union when CPU control is disabled.
        # Match the scope journal's semantic disabled state, preserving the
        # observed flags; never normalize a nonzero control flag to disabled.
        result["rate_bp"] = 0
    evidence._cpu(result, rate=rate)
    return result


def _accounting(value):
    if type(value) is not JobAccounting:
        _fail("accounting_observation_type_invalid")
    for number in asdict(value).values():
        _integer(number)
    return value


def _regular_record(path):
    """Read an existing regular, stable file with a bound before allocation."""
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or
            not before.st_ino or getattr(before, "st_file_attributes", 0) & 0x400 or
            not 0 < before.st_size <= MAX_RECORD_BYTES):
        _fail("fixture_file_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode):
            _fail("fixture_file_changed")
        raw = stream.read(MAX_RECORD_BYTES + 1)
        after = os.fstat(stream.fileno())
    current = path.lstat()
    # Windows path stat ctime can be birthtime while fstat ctime is change
    # time. Preserve both independent before/after signatures; compare only
    # fields with the same meaning across the path and original open handle.
    shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    fields = (*shared, "st_ctime_ns", "st_mode", "st_file_attributes")
    def signature(info, names=fields):
        return tuple(getattr(info, key, None) for key in names)
    if (len(raw) != before.st_size or len(raw) > MAX_RECORD_BYTES or
            signature(before) != signature(current) or signature(opened) != signature(after) or
            signature(before, shared) != signature(opened, shared)):
        _fail("fixture_file_changed")
    result = strict_json_loads(raw)
    if type(result) is not dict:
        _fail("fixture_record_invalid")
    return result


def _pins(case):
    generation = json.loads(case.spec.generation_json)
    command = case.spec.command
    sources = [source for source in command.fixture_sources if source.path == command.arguments[1]]
    if len(sources) != 1:
        _fail("fixture_pin_invalid")
    return dict(nonce=case.creation_nonce, scope_id=case.scope_id,
        job_name=case.scope.job_name, source_generation=generation["generation"],
        source_digest=generation["source_digest"], fixture_sha256=sources[0].sha256)


def _original_scope(case):
    if type(case) is not S1Case or type(case.scope) is not ExperimentNativeScope:
        _fail("original_case_scope_required")
    case._original()
    scope = case.scope
    if (case.provider.current_case is not case or scope.demand is not case.demand or
            scope.command is not case.spec.command or scope.scope_id != case.scope_id or
            scope.creation_nonce != case.creation_nonce or type(scope.job) is not NativeJob):
        _fail("original_scope_changed")
    case.demand._assert_native_preparation(scope)
    _fixture_directory(case)
    return scope


def _fixture_directory(case):
    for path in (case.directory, *case.directory.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            _fail("fixture_directory_changed")
    info = case.directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or case.directory.resolve(strict=True) != case.directory or
            (info.st_dev, info.st_ino) != case.spec.directory_identity):
        _fail("fixture_directory_changed")


def _identity(value):
    if type(value) is not dict or set(value) != {"pid", "created_filetime_100ns", "logon_id"}:
        _fail("fixture_identity_invalid")
    result = ProcessIdentity.from_dict(value)
    if result.to_dict() != value:
        _fail("fixture_identity_invalid")
    return result


def _bound(case, deadline):
    _integer(deadline, minimum=1)
    scope_deadline = int(case.scope.deadline * 1_000_000_000)
    if deadline > scope_deadline - 4_000_000_000:
        _fail("fixture_deadline_extended")
    return min(deadline, scope_deadline)


def _validate_ready(case, record, identity, role, deadline, *, status="ready", foreign=False):
    required = (_READY if status == "ready" else _EXIT) | ({"foreign_gate"} if foreign else set())
    if type(record) is not dict or set(record) != required:
        _fail("fixture_record_shape_invalid")
    if (_identity(record["identity"]) != identity or
            any(type(record[key]) is not type(value) or record[key] != value
                for key, value in identity.to_dict().items()) or
            any(type(record[key]) is not str or record[key] != value for key, value in _pins(case).items()) or
            type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            record["status"] != status or record["role"] != role or
            record["readiness_scope"] != "this_process_only" or record["in_expected_job"] is not True or
            identity.logon_id != case.provider.context.logon_id or
            type(record["deadline_monotonic_ns"]) is not int or record["deadline_monotonic_ns"] != deadline or
            type(record["deadline_monotonic"]) is not float or record["deadline_monotonic"] != deadline / 1_000_000_000 or
            type(record["maximum_cpu_work_seconds"]) not in (int, float) or
            record["maximum_cpu_work_seconds"] != case.spec.seconds or
            type(record["cooperative_cleanup_grace_seconds"]) is not int or
            record["cooperative_cleanup_grace_seconds"] != 4):
        _fail("fixture_binding_mismatch")
    parent = case.scope.launch.wrapper_witness.identity.pid if role == "root" else case.scope.launch.root_witness.identity.pid
    if type(record["parent_pid"]) is not int or record["parent_pid"] != parent:
        _fail("fixture_parent_mismatch")
    _bound(case, deadline)
    if status == "work_complete":
        _integer(record["work_chunks"])
        if (record["reason"] not in {"self_deadline", "stop_file", "foreign_host_probe"} or
                type(record["elapsed_seconds"]) not in (int, float) or
                not math.isfinite(record["elapsed_seconds"]) or record["elapsed_seconds"] < 0 or
                type(record["children_still_alive"]) is not int or record["children_still_alive"] != 0 or
                record["owned_handles_closed"] is not True):
            _fail("fixture_exit_unverified")


@dataclass(frozen=True)
class TreeObservation:
    root: ProcessIdentity
    children: tuple[ProcessIdentity, ...]
    deadline_ns: int
    records_json: str
    manifest_json: str

    @property
    def pids(self):
        return frozenset(identity.pid for identity in (self.root, *self.children))


def _tree(case, manifest, records):
    scope = case.scope
    root = scope.launch.root_witness
    if type(root) is not VerifiedProcess or root is scope.guardian or root is scope.launch.wrapper_witness:
        _fail("original_root_required")
    if (type(manifest) is not dict or set(manifest) != _TREE or
            type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or
            manifest["status"] != "tree_ready" or _identity(manifest["root_identity"]) != root.identity or
            any(type(manifest[key]) is not str or manifest[key] != value for key, value in _pins(case).items()) or
            type(manifest["child_identities"]) is not list or len(manifest["child_identities"]) > 63):
        _fail("tree_binding_mismatch")
    children = tuple(_identity(value) for value in manifest["child_identities"])
    identities = (root.identity, *children)
    if (len(identities) != case.spec.workers or len(set(identities)) != len(identities) or
            len({value.pid for value in identities}) != len(identities) or
            any(value.logon_id != root.identity.logon_id for value in children) or
            set(records) != {value.pid for value in identities}):
        _fail("tree_membership_mismatch")
    deadline = _bound(case, manifest["deadline_monotonic_ns"])
    for identity in identities:
        _validate_ready(case, records[identity.pid], identity,
            "root" if identity == root.identity else "leaf", deadline)
    return TreeObservation(root.identity, children, deadline,
        json.dumps(records, sort_keys=True, separators=(",", ":")),
        json.dumps(manifest, sort_keys=True, separators=(",", ":")))


def _membership(scope, tree):
    root = scope.launch.root_witness
    if (root.identity != tree.root or root.observe().status is not IdentityStatus.ALIVE or
            root.query_owned_job_membership(scope.job.handle) is not True):
        _fail("root_membership_unverified")
    pids = scope.job.active_pids()
    if (type(pids) is not tuple or any(type(value) is not int for value in pids) or
            len(pids) != len(tree.pids) or frozenset(pids) != tree.pids):
        _fail("job_membership_changed")
    accounting = _accounting(scope.job.accounting())
    if accounting.active_processes != len(tree.pids) or accounting.total_processes != len(tree.pids):
        _fail("job_lifetime_membership_changed")
    return accounting


def _ready(case):
    scope = _original_scope(case)
    until = min(int(scope.deadline * 1_000_000_000), time.monotonic_ns() + 10_000_000_000)
    while time.monotonic_ns() < until:
        scope.assert_covered()
        manifest_path = case.directory / "tree-ready.json"
        if manifest_path.exists():
            # Root publishes this immutable manifest only after all ready
            # files. Observe it first, then scan the complete set: a scan
            # preceding publication could legitimately miss the last child.
            manifest = _regular_record(manifest_path)
            paths = {}
            with os.scandir(case.directory) as entries:
                for count, entry in enumerate(entries, 1):
                    if count > MAX_DIRECTORY_ENTRIES:
                        _fail("fixture_directory_oversized")
                    if entry.name.startswith("ready-") and entry.name.endswith(".json"):
                        suffix = entry.name[6:-5]
                        if not suffix.isascii() or not suffix.isdecimal() or str(int(suffix)) != suffix:
                            _fail("fixture_filename_invalid")
                        paths[int(suffix)] = Path(entry.path)
                        if len(paths) > case.spec.workers:
                            _fail("fixture_membership_excess")
            records = {pid: _regular_record(path) for pid, path in paths.items()}
            tree = _tree(case, manifest, records)
            if time.monotonic_ns() >= tree.deadline_ns:
                _fail("fixture_deadline_expired")
            _membership(scope, tree)
            return tree
        if scope.launch.root_witness.observe().status is not IdentityStatus.ALIVE:
            _fail("root_exited_before_tree_ready")
        time.sleep(.05)
    _fail("fixture_readiness_deadline")


def _window(case, tree, *, capped=False):
    scope = _original_scope(case)
    rate = 2500 if capped else None
    def observe():
        if capped:
            _cpu(scope.observe_control(), rate=rate)
        else:
            scope.assert_covered()
            _cpu(scope.job.query_cpu())
        return _membership(scope, tree)
    initial = observe()
    start = time.monotonic_ns()
    cutoff = _bound(case, tree.deadline_ns)
    if start + WINDOW_NS >= cutoff:
        _fail("fixed_window_deadline")
    while True:
        current = time.monotonic_ns()
        if current >= cutoff:
            _fail("work_cutoff_reached")
        if current - start >= WINDOW_NS:
            break
        time.sleep(min(.25, (start + WINDOW_NS - current) / 1_000_000_000))
        observe()
    final = observe()
    end = time.monotonic_ns()
    if end >= cutoff:
        _fail("work_cutoff_reached")
    result = dict(start_ns=start, end_ns=end, cpu_start_100ns=initial.cpu_100ns,
        cpu_end_100ns=final.cpu_100ns, members_start=initial.active_processes,
        members_end=final.active_processes)
    evidence._window(result)
    return result


def _infrastructure(scope):
    observations = []
    for witness in (scope.guardian, scope.launch.wrapper_witness):
        if type(witness) is not VerifiedProcess:
            _fail("original_infrastructure_required")
        member = witness.is_in_job(scope.job.handle)
        if type(member) is not bool:
            _fail("infrastructure_membership_unknown")
        observations.append(dict(identity=witness.identity.to_dict(), in_work_job=member))
    if observations[0]["identity"] == observations[1]["identity"] or any(row["in_work_job"] for row in observations):
        _fail("infrastructure_in_work_job")
    return observations


def _baseline(scope, context):
    limits, security = scope.job.query_limits(), scope.job.query_security()
    if type(limits) is not JobLimits or limits.limit_flags != 0 or limits.ui_restrictions != 0:
        _fail("job_other_limits")
    if (type(security) is not JobSecurity or security.logon_sid != context.logon_id or
            security.descriptor_control & 0x1004 != 0x1004 or security.descriptor_control & 0x0009 or
            security.descriptor_revision != 1 or security.acl_revision != 2 or security.ace_count != 1 or
            security.ace_type != 0 or security.ace_flags != 0 or security.access_mask != 0x001F003F or
            security.handle_flags & 1):
        _fail("job_security_unverified")
    return asdict(limits), security, _cpu(scope.job.query_cpu())


def _reopened_restore(scope):
    principal = scope.job
    probe = scope.open_probe()
    if type(probe) is not NativeJob or principal.closed or probe is principal or probe.handle == principal.handle:
        _fail("original_control_probe_required")
    reopened = _cpu(probe.query_cpu(), rate=2500)
    _cpu(principal.query_cpu(), rate=2500)
    restored = _cpu(scope.restore(through=probe))
    _cpu(probe.query_cpu())
    _cpu(principal.query_cpu())
    nonce = probe.nonce
    scope.close_probe(probe)
    if not probe.closed or principal.closed:
        _fail("probe_close_unverified")
    return reopened, restored, nonce


def _wait_root(case, *, maximum_seconds=10):
    root = case.scope.launch.root_witness
    if type(root) is not VerifiedProcess:
        _fail("original_root_required")
    until = min(int(case.scope.deadline * 1_000_000_000),
        time.monotonic_ns() + maximum_seconds * 1_000_000_000)
    while time.monotonic_ns() < until:
        observed = root.observe()
        if observed.identity != root.identity or observed.status is IdentityStatus.UNKNOWN:
            _fail("root_exit_unknown")
        if observed.status is IdentityStatus.DEAD:
            return root.exit_code()
        case.scope.assert_covered()
        _cpu(case.scope.job.query_cpu())
        time.sleep(.05)
    _fail("root_exit_deadline")


@dataclass(frozen=True)
class EmptyObservation:
    cpu: CpuState
    accounting: JobAccounting
    pids: tuple[int, ...]
    root: ProcessIdentity | None
    root_exit_code: int | None


def _empty_before_close(case):
    """Actual empty Job readback while its principal still belongs to scope."""
    scope = case.scope
    scope.restore()
    case._stop()
    while True:
        cpu = scope.job.query_cpu()
        accounting = _accounting(scope.job.accounting())
        pids = scope.job.active_pids()
        root = scope.launch.root_witness
        if root is not None and type(root) is not VerifiedProcess:
            _fail("original_root_required")
        observed = None if root is None else root.observe()
        if observed is not None and (observed.identity != root.identity or observed.status is IdentityStatus.UNKNOWN):
            _fail("root_exit_unknown")
        dead = root is None or observed.status is IdentityStatus.DEAD
        if accounting.active_processes == 0 and pids == () and dead:
            _cpu(cpu)
            code = None if root is None else _integer(root.exit_code(), maximum=0xffffffff)
            return EmptyObservation(cpu, accounting, pids, None if root is None else root.identity, code)
        if time.monotonic() >= scope.deadline:
            _fail("cleanup_empty_deadline")
        time.sleep(.05)


def _cleanup_observation(case, empty):
    completion, operation, scope = case.completion, case.release_operation, case.scope
    if (type(completion) is not NativeScopeCompletion or completion.owner is not scope or
            type(operation) is not ExperimentReleaseOperation or operation.completion is not completion or
            operation.demand is not case.demand or operation._completed is not True or
            case.cleanup_result.get("released") is not True or type(empty) is not EmptyObservation):
        _fail("original_cleanup_required")
    completion.assert_original()
    cpu, accounting, pids = empty.cpu, _accounting(empty.accounting), empty.pids
    _cpu(cpu)
    terminal = completion.snapshot()["terminal"]
    # Registered scope completions retain ScopeJournal's validated SQLite
    # INTEGER seal (0/1), unlike the boolean in early-preparation completions.
    if (type(terminal["launch_sealed"]) is not int or terminal["launch_sealed"] != 1 or
            terminal["state"] not in {"NEVER_LAUNCHED", "FINISHED"} or
            terminal["total_processes"] != accounting.total_processes or pids != () or
            accounting.active_processes != 0):
        _fail("cleanup_native_binding_changed")
    expected = 0 if case.spec.kind == "empty_probe" else case.spec.workers
    if (accounting.total_processes != expected or
            (expected == 0 and (terminal["state"] != "NEVER_LAUNCHED" or terminal["root"] is not None or
                empty.root is not None or empty.root_exit_code is not None)) or
            (expected != 0 and (terminal["state"] != "FINISHED" or empty.root is None or
                terminal["root"] != empty.root.to_dict() or terminal["root_exit_code"] != 0 or
                empty.root_exit_code != 0))):
        _fail("cleanup_workload_exit_unverified")
    last = terminal["last_applied_cpu"] or terminal["original_cpu"]
    if last != _cpu(cpu):
        _fail("cleanup_cpu_changed")
    # Read through the original release-only connection, preserving the real
    # receipt/postimage validator and original SQL-close custody. No PID/TTL or
    # copied receipt can create this operation or grant this connection scope.
    with operation._scope("READ"), operation.store._connection() as conn:
        conn.execute("BEGIN")
        daily_generation.revalidate_transaction(conn, db_path=operation.ledger_path)
        record = operation._verify_committed(conn)
        live = conn.execute("SELECT count(*) FROM reservations WHERE id=? OR execution_id=? OR request_key=?",
            (record["reservation_id"], record["execution_id"], record["request_key"])).fetchone()[0]
        if conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='worker_reservations'").fetchone()[0]:
            live += conn.execute("SELECT count(*) FROM worker_reservations WHERE execution_id=?",
                (record["execution_id"],)).fetchone()[0]
        conn.rollback()
    post = record["postimage"]
    if (record["completion_digest"] != completion.digest or post["managed"]["state"] != "CANCELLED_BEFORE_START" or
            post["exclusion"] is None or post["exclusion"]["phase"] != "CLOSED"):
        _fail("cleanup_postimage_changed")
    result = dict(cpu_flags=last["flags"], active_processes=accounting.active_processes,
        pending_intents=int(terminal["pending_target_cpu"] is not None),
        unsettled_handles=int(not scope._native_closed) + int(not operation._close_positive) + len(operation._connections),
        live_allocations=live)
    evidence._cleanup(result)
    return result


def _exit_records(case, tree, foreign):
    """Match complete records to the original root-observed child identities.

    These files add workload completion evidence only. Original native close
    and verified daily release have already completed before this is called.
    """
    if case.spec.kind == "empty_probe":
        return {}
    _fixture_directory(case)
    if case.spec.kind == "foreign_parent":
        if type(foreign) is not dict:
            _fail("foreign_exit_binding_missing")
        root = case.scope.launch.root_witness.identity
        identities, deadline = (root,), foreign["deadline_monotonic_ns"]
    else:
        if type(tree) is not TreeObservation:
            _fail("tree_exit_binding_missing")
        root, identities, deadline = tree.root, (tree.root, *tree.children), tree.deadline_ns
    paths = {}
    with os.scandir(case.directory) as entries:
        for count, entry in enumerate(entries, 1):
            if count > MAX_DIRECTORY_ENTRIES:
                _fail("fixture_directory_oversized")
            if entry.name.startswith("exit-") and entry.name.endswith(".json"):
                suffix = entry.name[5:-5]
                if not suffix.isascii() or not suffix.isdecimal() or str(int(suffix)) != suffix:
                    _fail("fixture_filename_invalid")
                paths[int(suffix)] = Path(entry.path)
    if set(paths) != {identity.pid for identity in identities}:
        _fail("fixture_exit_membership_mismatch")
    records = {}
    for identity in identities:
        record = _regular_record(paths[identity.pid])
        _validate_ready(case, record, identity, "root" if identity == root else "leaf", deadline,
            status="work_complete", foreign=foreign is not None)
        if foreign is not None:
            if record["reason"] != "foreign_host_probe" or record["foreign_gate"] != foreign["foreign_gate"]:
                _fail("foreign_exit_changed")
        elif record["reason"] not in {"self_deadline", "stop_file"}:
            _fail("fixture_exit_reason_invalid")
        if case.spec.kind == "self_stop" and record["reason"] != "self_deadline":
            _fail("self_stop_failed")
        records[str(identity.pid)] = record
    return records


class S1Measurements:
    def __init__(self, provider, directory, context):
        if type(provider) is not S1SerialProvider or type(context) is not evidence.LiveCapabilityContext:
            _fail("original_provider_context_required")
        provider._original()
        directory = Path(directory)
        if (context is not provider.context or directory != provider.directory or
                directory.resolve(strict=True) != provider.directory or provider._cases or
                getattr(provider, "_s1_measurements_owner", None) is not None):
            _fail("original_measurement_run_required")
        self.provider, self.directory, self.context = provider, directory, context
        self.errors = []
        self._started = False
        provider._s1_measurements_owner = self

    def _await(self, case):
        while True:
            result = case.poll_admission()
            if result["allowed"]:
                return _original_scope(case)
            time.sleep(.25)  # Same original queue context; no scope clock exists.

    def _cleanup(self, case, tree=None, foreign=None):
        empty = None
        scope = case.scope
        if type(scope) is ExperimentNativeScope and scope._registered and not scope._native_closed:
            try:
                empty = _empty_before_close(case)
            except BaseException as error:
                case._retain(error)
        while True:
            try:
                result = case.recover_once()
            except BaseException as error:
                case._retain(error)
                raise NativeRunUnsettled(self.provider, additional_custody=error) from error
            if result is not None:
                break
            if type(scope) is not ExperimentNativeScope or time.monotonic() >= scope.deadline:
                raise NativeRunUnsettled(self.provider)
            time.sleep(.05)
        if case.errors:
            raise NativeRunBlocked("native_s1_case_failed") from case.errors[0]
        try:
            return _cleanup_observation(case, empty), _exit_records(case, tree, foreign)
        except BaseException as error:
            case._retain(error)
            operation = case.release_operation
            if type(operation) is ExperimentReleaseOperation and (
                    operation._connections or operation._quarantine is not None):
                raise NativeRunUnsettled(self.provider, additional_custody=error) from error
            raise

    def _case(self, kind, iteration=None):
        case = None
        primary = None
        measured, details, cleanup = {}, {}, None
        tree, foreign = None, None
        try:
            case = self.provider.start_case(kind)
            scope = self._await(case)
            limits, security, initial = _baseline(scope, self.context)
            details.update(limits=limits, security=asdict(security), initial=initial,
                infrastructure=_infrastructure(scope))
            if kind == "empty_probe":
                empty = _accounting(scope.job.accounting())
                if empty.active_processes != 0 or empty.total_processes != 0 or scope.job.active_pids() != ():
                    _fail("empty_job_baseline_invalid")
                details["applied"] = _cpu(scope.set_cpu_rate(2500), rate=2500)
                details["reopened"], details["restored"], details["reopened_nonce"] = _reopened_restore(scope)
            else:
                started = time.monotonic_ns()
                root = scope.launch_once()
                if root is not scope.launch.root_witness:
                    _fail("original_root_changed")
                if kind == "foreign_parent":
                    code = _wait_root(case)
                    probe = _regular_record(case.directory / "foreign-probe.json")
                    deadline = probe["deadline_monotonic_ns"]
                    _validate_ready(case, probe, root.identity, "root", deadline, foreign=True)
                    gate = probe["foreign_gate"]
                    if (code != 0 or type(gate) is not dict or set(gate) != {"status", "reason", "win32_error"} or
                            gate["status"] != "unsupported" or gate["reason"] != "host_foreign_parent_job" or
                            gate["win32_error"] is not None and (type(gate["win32_error"]) is not int or
                                not 0 <= gate["win32_error"] <= 0xffffffff) or
                            root.query_owned_job_membership(scope.job.handle) is not True):
                        _fail("foreign_parent_not_rejected")
                    details["foreign_probe"] = probe
                    foreign = probe
                    accounting = _accounting(scope.job.accounting())
                    if accounting.total_processes != 1:
                        _fail("foreign_probe_additional_launch")
                    measured.update(foreign_parent_jobs=int(probe["in_expected_job"]),
                        foreign_parent_launches=accounting.total_processes - 1)
                else:
                    tree = _ready(case)
                    details.update(tree=json.loads(tree.manifest_json), ready=json.loads(tree.records_json))
                    if kind == "self_stop":
                        code = _wait_root(case)
                        elapsed = time.monotonic_ns() - started
                        exit_record = _regular_record(case.directory / f"exit-{root.identity.pid}.json")
                        _validate_ready(case, exit_record, root.identity, "root", tree.deadline_ns, status="work_complete")
                        if code != 0 or exit_record["reason"] != "self_deadline":
                            _fail("self_stop_failed")
                        measured.update(self_stop_elapsed_ns=elapsed, self_stop_exit_code=code)
                        details["exit"] = exit_record
                    else:
                        measured.update(iteration=iteration, nonce=scope.creation_nonce,
                            denominator=self.context.logical_processors, rate_bp=2500,
                            worker_count=case.spec.workers, initial=initial)
                        measured["uncapped_window"] = _window(case, tree)
                        baseline = evidence._window(measured["uncapped_window"])
                        target, tolerance = self.context.logical_processors * .25, max(.15, self.context.logical_processors * .025)
                        if baseline < case.spec.workers * .9 or baseline < target + tolerance + .25 or baseline > self.context.logical_processors:
                            _fail("canary_not_saturated")
                        measured["applied"] = _cpu(scope.set_cpu_rate(2500), rate=2500)
                        measured["capped_window"] = _window(case, tree, capped=True)
                        if abs(evidence._window(measured["capped_window"]) - target) > tolerance:
                            _fail("cpu_effect_failed")
                        measured["reopened"], measured["restored"], reopened_nonce = _reopened_restore(scope)
                        measured["restored_window"] = _window(case, tree)
                        restored = evidence._window(measured["restored_window"])
                        if restored < baseline * .9 or restored < target + tolerance + .25 or restored > self.context.logical_processors:
                            _fail("restore_effect_failed")
                        measured["containment"] = dict(before_user_code_members=len(tree.pids),
                            extended_limit_flags=limits["limit_flags"], ui_restrictions=limits["ui_restrictions"],
                            reopened_nonce=reopened_nonce, allowed_logon_id=security.logon_sid,
                            protected_dacl=int(bool(security.descriptor_control & 0x1000)), allow_ace_count=security.ace_count,
                            infra_in_work_job=sum(int(row["in_work_job"]) for row in details["infrastructure"]))
        except BaseException as error:
            primary = error
            case = case or self.provider.current_case
            if case is not None:
                case._retain(error)
        finally:
            if case is not None:
                try:
                    cleanup, details["exits"] = self._cleanup(case, tree, foreign)
                except BaseException as error:
                    if isinstance(error, NativeRunUnsettled):
                        self.errors.append(error)
                        raise error from primary or error.__cause__
                    if primary is None:
                        primary = error
                    else:
                        self.errors.append(error)
        if primary is not None:
            self.errors.append(primary)
            # A failure record cannot substitute for a completed measurement.
            # Native custody must already be positively closed before writing.
            if case is not None and case._closed:
                try:
                    _write_new(case.directory / "measurement-failure.json", dict(case=kind,
                        errors=error_evidence(primary, stage="measurement")))
                except BaseException as logging_error:
                    self.errors.append(logging_error)
            raise primary
        measured["cleanup"] = cleanup
        try:
            _write_new(case.directory / "native-result.json", dict(case=kind, scope_id=case.scope_id,
                measurements=measured, details=details, cleanup=cleanup))
        except BaseException as error:
            case._retain(error)
            self.errors.append(error)
            raise
        return measured

    def run(self):
        if self._started:
            _fail("measurement_already_started")
        self._started = True
        self_stop = self._case("self_stop")
        empty = self._case("empty_probe")
        foreign = self._case("foreign_parent")
        data = dict(prerequisites=dict(self_stop_elapsed_ns=self_stop["self_stop_elapsed_ns"],
            self_stop_exit_code=self_stop["self_stop_exit_code"], empty_restore=empty["cleanup"],
            foreign_parent_jobs=foreign["foreign_parent_jobs"], foreign_parent_launches=foreign["foreign_parent_launches"]),
            rounds=[self._case("round", index) for index in range(ROUNDS)])
        evidence._s1(data, self.context)
        return data


def produce_s1(provider, directory, context):
    return S1Measurements(provider, directory, context).run()
