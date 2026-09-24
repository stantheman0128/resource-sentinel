"""Closed experiment cleanup history, never original release authority.

All functions operate on data or an existing SQLite transaction. Nothing here
opens a connection, installs a schema, mutates a row, queries a native owner or
mints a completion. The original typed release operation owns first publication
and the fixed INSERT UDF. A valid historical tuple is only an observation.

cleanup_digest binds original completion/demand/operation, independently of the
postimage. CLOSED exclusions refer to it. receipt_sha256 binds the entire closed
record, including pre/postimages; it is deliberately a different digest.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
from uuid import UUID

from . import daily_generation, experiment_demand, experiment_exclusion
from .contracts import ProcessIdentity, ResourceDemand
from .experiment_scope_journal import ScopeJournal, _BINDING as _SCOPE_BINDING, _binding as _scope_binding


TABLE = "adaptive_experiment_cleanup_receipts"
# Match daily_retirement_inventory. Counts are per table; byte accounting is
# additive across every projected row. Integrators must add bytes_used to their
# existing inventory budget, not give this reader a separate 16 MiB allowance.
MAX_HISTORY = 4096
MAX_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_CELL_BYTES = 65536
DISPOSITIONS = frozenset({"BEFORE_NATIVE", "PREPARATION_CLOSED", "WRAPPER_NOT_CREATED", "NEVER_LAUNCHED", "FINISHED"})
FIELDS = ("receipt_id", "operation_id", "schema_version", "experiment_id", "execution_id",
    "reservation_id", "request_key", "disposition", "receipt_json", "receipt_sha256")
TABLE_SQL = """CREATE TABLE adaptive_experiment_cleanup_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL, operation_id TEXT UNIQUE NOT NULL,
    schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
    experiment_id TEXT UNIQUE NOT NULL, execution_id TEXT UNIQUE NOT NULL,
    reservation_id TEXT UNIQUE NOT NULL, request_key TEXT UNIQUE NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('BEFORE_NATIVE','PREPARATION_CLOSED',
        'WRAPPER_NOT_CREATED','NEVER_LAUNCHED','FINISHED')),
    receipt_json TEXT NOT NULL CHECK(typeof(receipt_json)='text' AND length(CAST(receipt_json AS BLOB))<=2097152),
    receipt_sha256 TEXT UNIQUE NOT NULL CHECK(length(receipt_sha256)=64 AND receipt_sha256 NOT GLOB '*[^0-9a-f]*'))"""
TRIGGER_SQL = {
    "experiment_cleanup_receipt_insert_guard": """CREATE TRIGGER experiment_cleanup_receipt_insert_guard
        BEFORE INSERT ON adaptive_experiment_cleanup_receipts
        WHEN sentinel_experiment_receipt_owned(NEW.receipt_id,NEW.receipt_sha256) IS NOT 1
        BEGIN SELECT RAISE(ABORT,'experiment_original_release_required'); END""",
    "experiment_cleanup_receipt_update_guard": """CREATE TRIGGER experiment_cleanup_receipt_update_guard
        BEFORE UPDATE ON adaptive_experiment_cleanup_receipts
        BEGIN SELECT RAISE(ABORT,'experiment_cleanup_history_immutable'); END""",
    "experiment_cleanup_receipt_delete_guard": """CREATE TRIGGER experiment_cleanup_receipt_delete_guard
        BEFORE DELETE ON adaptive_experiment_cleanup_receipts
        BEGIN SELECT RAISE(ABORT,'experiment_cleanup_history_immutable'); END""",
}
MANAGED_FIELDS = ("execution_id", "task_id", "session_id", "principal_id", "logon_id", "allocation_kind",
    "reservation_id", "parent_execution_id", "spec_hash", "wrapper_pid", "wrapper_created_filetime_100ns",
    "root_pid", "root_created_filetime_100ns", "job_name", "role", "priority", "coverage", "state",
    "state_revision", "guardian_epoch", "launch_in_flight", "launch_sealed", "claim_token_hash",
    "claim_consumed", "root_outcome", "hold_reason", "created_at", "heartbeat_at", "finished_at",
    "cancel_requested_at", "requested_cpu_units", "requested_physical_bytes", "requested_commit_bytes",
    "requested_io_slots", "floor_cpu_units", "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots",
    "admission_binding_hash", "ipc_auth_key", "job_nonce")
ALLOCATION_FIELDS = ("id", "request_key", "owner_pid", "owner_started", "tool_use_id", "repo",
    "command_signature", "command_text", "resource_class", "priority", "priority_rank", "cpu_units",
    "ram_gib", "io_slots", "created_at", "heartbeat_at", "expires_at", "lease_duration_sec", "spec_hash",
    "execution_id", "lifecycle_managed", "physical_bytes", "commit_bytes", "managed_spec_hash",
    "writer_protocol", "writer_revision")
QUEUE_FIELDS = ("request_key", "owner_pid", "owner_started", "tool_use_id", "repo", "command_signature",
    "command_text", "resource_class", "priority", "priority_rank", "cpu_units", "ram_gib", "io_slots",
    "queued_at", "heartbeat_at", "spec_hash", "commit_bytes", "managed_execution_id", "managed_binding_hash")
ARCHIVE_FIELDS = ("reservation_id", "request_key", "owner_pid", "repo", "command_signature", "resource_class",
    "priority", "cpu_units", "ram_gib", "io_slots", "started_at", "ended_at", "outcome")
_IMAGE_FIELDS = (set(MANAGED_FIELDS) - {"ipc_auth_key", "claim_token_hash"}) | {
    "ipc_auth_key_sha256", "claim_token_hash_sha256"}
_RECORD_FIELDS = {"schema_version", "receipt_id", "operation_id", "experiment_id", "execution_id",
    "reservation_id", "request_key", "suite", "disposition", "demand_binding_sha256", "completion_digest",
    "cleanup_digest", "completion", "policy", "transaction_time", "preimage", "preimage_sha256",
    "postimage", "postimage_sha256"}
_DEMAND_FIELDS = {"experiment_id", "suite", "scope_sha256", "requested", "execution_id", "request_key",
    "admission_binding_hash", "spec_hash", "caller_identity", "ledger_path", "ledger_identity",
    "scope_directory", "scope_directory_identity", "source_root", "generation", "generation_binding"}
_GENERATION_FIELDS = {"singleton", "schema_version", "generation", "state", "source_digest", "config_digest",
    "source_manifest_json", "source_root", "ledger_path", "owner_identity_json", "ledger_identity_json",
    "readiness_instance_id"}
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


class ExperimentHistoryError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_history_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise ExperimentHistoryError(reason)


def _shape(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        _fail("shape_invalid")


def _integer(value, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        _fail("integer_invalid")
    return value


def _number(value, minimum=0):
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value >= minimum
    except OverflowError:
        valid = False
    if not valid:
        _fail("number_invalid")
    return value


def _text(value, maximum=128, *, empty=False):
    if type(value) is not str or not (0 if empty else 1) <= len(value) <= maximum or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        _fail("text_invalid")
    return value


def _uuid(value):
    try:
        if type(value) is str and str(UUID(value)) == value and UUID(value).int:
            return value
    except (ValueError, TypeError, AttributeError):
        pass
    _fail("uuid_invalid")


def _hash(value):
    if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
        _fail("digest_invalid")
    return value


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail("json_invalid")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("json_duplicate_key")
        result[key] = value
    return result


def _json(value, limit=MAX_CELL_BYTES):
    if type(value) is not str or len(value.encode("utf-8")) > limit:
        _fail("json_bound")
    try:
        result = json.loads(value, object_pairs_hook=_pairs,
            parse_constant=lambda _: _fail("json_invalid"))
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail("json_invalid")
    if _canonical(result) != value:
        _fail("json_noncanonical")
    return result


def _same(left, right):
    return _canonical(left) == _canonical(right)


def _digest(domain, value):
    return hashlib.sha256((domain + "\n" + _canonical(value)).encode("ascii")).hexdigest()


def image_digest(kind, image):
    if kind not in {"preimage", "postimage"}:
        _fail("image_kind_invalid")
    return _digest("experiment-release-" + kind + "-v1", image)


def cleanup_digest(*, receipt_id, operation_id, reservation_id, demand_binding_sha256, completion_digest, demand):
    """Data digest, independent of postimage; never a native completion capability."""
    _uuid(receipt_id)
    _uuid(operation_id)
    _text(reservation_id)
    _hash(demand_binding_sha256)
    _hash(completion_digest)
    _validate_demand(demand)
    return _digest("experiment-cleanup-binding-v1", dict(receipt_id=receipt_id, operation_id=operation_id,
        reservation_id=reservation_id, demand_binding_sha256=demand_binding_sha256,
        completion_digest=completion_digest, demand=demand))


def _identity(value):
    _shape(value, {"pid", "created_filetime_100ns", "logon_id"})
    _integer(value["pid"], 1, (1 << 32) - 1)
    if type(value["created_filetime_100ns"]) is not str:
        _fail("identity_invalid")
    try:
        result = ProcessIdentity.from_dict(value)
    except (TypeError, ValueError, KeyError):
        _fail("identity_invalid")
    if (not _same(result.to_dict(), value) or re.fullmatch(r"S-1-5-5-[0-9]{1,10}-[0-9]{1,10}", result.logon_id) is None or
            any(int(part) > 0xFFFFFFFF for part in result.logon_id.split("-")[-2:])):
        _fail("identity_invalid")
    return result


def _file_identity(value):
    if type(value) is not list or len(value) != 2:
        _fail("file_identity_invalid")
    _integer(value[0], 0, (1 << 128) - 1)
    _integer(value[1], 1, (1 << 128) - 1)


def _resources(value):
    _shape(value, {"cpu_units", "physical_bytes", "commit_bytes", "io_slots"})
    _number(value["cpu_units"])
    for key in ("physical_bytes", "commit_bytes", "io_slots"):
        _integer(value[key])
    try:
        ResourceDemand.from_dict(value)
    except (ValueError, TypeError):
        _fail("resources_invalid")


def _validate_demand(demand):
    _shape(demand, _DEMAND_FIELDS)
    for key in ("experiment_id", "execution_id"):
        _uuid(demand[key])
    _text(demand["request_key"])
    if type(demand["suite"]) is not str or demand["suite"] not in {"S1", "S2", "S3", "P4", "P5", "P6"}:
        _fail("suite_invalid")
    for key in ("scope_sha256", "admission_binding_hash", "spec_hash"):
        _hash(demand[key])
    _resources(demand["requested"])
    _identity(demand["caller_identity"])
    for key in ("ledger_identity", "scope_directory_identity"):
        _file_identity(demand[key])
    for key in ("ledger_path", "scope_directory", "source_root"):
        _text(demand[key], 32768)
        if not Path(demand[key]).is_absolute() or ".." in Path(demand[key]).parts:
            _fail("path_invalid")
    if (Path(demand["scope_directory"]) == Path(demand["ledger_path"]).parent or
            Path(demand["ledger_path"]).parent in Path(demand["scope_directory"]).parents):
        _fail("path_invalid")
    row = demand["generation_binding"]
    _shape(row, _GENERATION_FIELDS)
    if type(row["singleton"]) is not int or row["singleton"] != 1 or type(row["schema_version"]) is not int or row["schema_version"] != 1 or row["state"] != "ACTIVE":
        _fail("generation_invalid")
    _uuid(row["generation"])
    _uuid(row["readiness_instance_id"])
    _hash(row["source_digest"])
    _hash(row["config_digest"])
    _identity(_json(row["owner_identity_json"], 1024))
    manifest_data = _json(row["source_manifest_json"], 1024 * 1024)
    try:
        manifest = daily_generation.SourceManifest.from_dict(manifest_data)
    except (ValueError, TypeError, RuntimeError):
        _fail("generation_invalid")
    if (manifest.digest != row["source_digest"] or row["ledger_path"] != demand["ledger_path"] or
            row["source_root"] != demand["source_root"] or
            not _same(_json(row["ledger_identity_json"]), [str(value) for value in demand["ledger_identity"]]) or
            not _same(demand["generation"], {key: row[key] for key in ("generation", "source_digest", "config_digest")})):
        _fail("generation_changed")


def managed_image(row):
    """Exact managed row with two credential fields replaced by irreversible hashes."""
    row = dict(row)
    _shape(row, MANAGED_FIELDS)
    key, claim = row.pop("ipc_auth_key"), row.pop("claim_token_hash")
    if type(key) is not bytes or len(key) != 32 or type(claim) is not str or claim != "" and re.fullmatch("[0-9a-f]{64}", claim) is None:
        _fail("credential_binding_invalid")
    row["ipc_auth_key_sha256"] = hashlib.sha256(key).hexdigest()
    row["claim_token_hash_sha256"] = hashlib.sha256(claim.encode("ascii")).hexdigest()
    return row


def archive_image(allocation, now):
    _shape(allocation, ALLOCATION_FIELDS)
    _number(now)
    return dict(reservation_id=allocation["id"], request_key=allocation["request_key"],
        owner_pid=allocation["owner_pid"], repo=allocation["repo"], command_signature=allocation["command_signature"],
        resource_class=allocation["resource_class"], priority=allocation["priority"], cpu_units=allocation["cpu_units"],
        ram_gib=allocation["ram_gib"], io_slots=allocation["io_slots"], started_at=allocation["created_at"],
        ended_at=now, outcome="managed_cancelled_before_start")


def cancellation_image(managed, now):
    """Deterministic terminal image; no arbitrary caller-supplied terminal fields."""
    _shape(managed, _IMAGE_FIELDS)
    _integer(managed["state_revision"], 0, (1 << 63) - 2)
    return managed | dict(state="CANCELLED_BEFORE_START", state_revision=managed["state_revision"] + 1,
        finished_at=now, cancel_requested_at=now, launch_sealed=1, launch_in_flight=0,
        claim_consumed=1, claim_token_hash_sha256=_EMPTY_HASH, hold_reason=None)


def _metadata(demand, reservation_id):
    caller, row = demand["caller_identity"], demand["generation_binding"]
    value = dict(experiment_id=demand["experiment_id"], schema_version=1, execution_id=demand["execution_id"],
        reservation_id=reservation_id, request_key=demand["request_key"], suite=demand["suite"],
        scope_sha256=demand["scope_sha256"], scope_directory=demand["scope_directory"],
        scope_identity_json=_canonical(demand["scope_directory_identity"]), source_generation=row["generation"],
        source_digest=row["source_digest"], config_digest=row["config_digest"],
        ledger_identity_json=_canonical(demand["ledger_identity"]), owner_pid=caller["pid"],
        owner_birth=caller["created_filetime_100ns"], owner_logon_id=caller["logon_id"],
        spec_hash=demand["spec_hash"], admission_binding_hash=demand["admission_binding_hash"],
        demand_json=_canonical(demand["requested"]), state="ADMITTED", revision=0)
    return value | {"binding_sha256": hashlib.sha256(_canonical(value).encode()).hexdigest()}


def _validate_managed(pre, demand, reservation_id):
    _shape(pre, _IMAGE_FIELDS)
    caller = demand["caller_identity"]
    for key in ("task_id", "session_id", "principal_id"):
        _text(pre[key], 128)
    expected = dict(execution_id=demand["execution_id"], logon_id=caller["logon_id"], allocation_kind="direct",
        reservation_id=reservation_id, parent_execution_id=None, spec_hash=demand["spec_hash"],
        wrapper_pid=caller["pid"], wrapper_created_filetime_100ns=caller["created_filetime_100ns"],
        root_pid=None, root_created_filetime_100ns=None, job_name=None, job_nonce=None, role="background",
        priority="P2", coverage="unmanaged", guardian_epoch="", launch_in_flight=0, launch_sealed=0,
        claim_consumed=0, root_outcome=None, finished_at=None, cancel_requested_at=None,
        admission_binding_hash=demand["admission_binding_hash"])
    if not _same({key: pre[key] for key in expected}, expected):
        _fail("managed_binding_changed")
    if (pre["state"] == "RESERVED" and pre["hold_reason"] is not None or
            pre["state"] == "UNCERTAIN_HOLD" and pre["hold_reason"] != "reservation_expired" or
            pre["state"] not in {"RESERVED", "UNCERTAIN_HOLD"}):
        _fail("managed_state_invalid")
    _integer(pre["state_revision"])
    _number(pre["created_at"])
    _number(pre["heartbeat_at"], pre["created_at"])
    _hash(pre["ipc_auth_key_sha256"])
    _hash(pre["claim_token_hash_sha256"])
    if pre["claim_token_hash_sha256"] == _EMPTY_HASH:
        _fail("claim_preimage_invalid")
    requested = {key: pre["requested_" + key] for key in demand["requested"]}
    floor = {key: pre["floor_" + key] for key in demand["requested"]}
    _resources(requested)
    _resources(floor)
    expected_requested = demand["requested"] | {"cpu_units": float(demand["requested"]["cpu_units"])}
    if not _same(requested, expected_requested) or any(floor[key] < value for key, value in requested.items()):
        _fail("managed_demand_changed")


def _validate_allocation(value, demand, reservation_id):
    _shape(value, ALLOCATION_FIELDS)
    expected = dict(id=reservation_id, request_key=demand["request_key"], execution_id=demand["execution_id"],
        lifecycle_managed=1, owner_pid=demand["caller_identity"]["pid"], command_text="",
        priority="P2", priority_rank=2, tool_use_id="managed-v1:" + demand["execution_id"],
        managed_spec_hash=demand["spec_hash"], repo="resource-sentinel-native-verification", resource_class="HEAVY",
        command_signature=demand["spec_hash"][:20],
        owner_started=(int(demand["caller_identity"]["created_filetime_100ns"]) - 116444736000000000) / 10_000_000)
    expected.update(demand["requested"] | {"cpu_units": float(demand["requested"]["cpu_units"])})
    if not _same({key: value[key] for key in expected}, expected):
        _fail("allocation_changed")
    for key in ("repo", "resource_class", "command_signature", "spec_hash"):
        _text(value[key], 256)
    for key in ("created_at", "heartbeat_at", "expires_at", "ram_gib"):
        _number(value[key])
    if value["lease_duration_sec"] is not None:
        _number(value["lease_duration_sec"])
    _integer(value["writer_protocol"], 1, 1)
    _integer(value["writer_revision"])
    if (value["heartbeat_at"] < value["created_at"] or value["expires_at"] < value["created_at"] or
            value["ram_gib"] != value["physical_bytes"] / (1 << 30)):
        _fail("allocation_invalid")
    request_values = {key: value[key] for key in ("repo", "command_signature", "resource_class", "priority",
        "cpu_units", "ram_gib", "io_slots", "commit_bytes")}
    request_key = f"{value['owner_pid']}:{value['owner_started']:.3f}:{value['repo']}:{value['tool_use_id']}"
    if (value["spec_hash"] != hashlib.sha256(_canonical(request_values).encode()).hexdigest() or
            value["request_key"] != hashlib.sha256(request_key.encode()).hexdigest()):
        _fail("allocation_request_changed")


def _validate_queue(value, allocation, demand):
    if value is None:
        return
    _shape(value, QUEUE_FIELDS)
    expected = {key: allocation[key] for key in QUEUE_FIELDS if key in allocation and key not in {"spec_hash", "heartbeat_at"}}
    expected.update(spec_hash="managed-v1:" + demand["admission_binding_hash"],
        managed_execution_id=demand["execution_id"], managed_binding_hash=demand["admission_binding_hash"])
    if not _same({key: value[key] for key in expected}, expected):
        _fail("queue_changed")
    _number(value["queued_at"])
    _number(value["heartbeat_at"], value["queued_at"])


def _exclusion_binding(row):
    _shape(row, experiment_exclusion._FIELDS)
    try:
        binding = experiment_exclusion.ExperimentExclusionBinding(
            experiment_id=row["experiment_id"], daily_execution_id=row["daily_execution_id"],
            reservation_id=row["reservation_id"], source_generation=row["source_generation"],
            scope_execution_id=row["scope_execution_id"], isolated_ledger_path=row["isolated_ledger_path"],
            isolated_ledger_identity=tuple(_json(row["isolated_ledger_identity_json"])),
            isolated_policy_instance_id=row["isolated_policy_instance_id"], job_name=row["job_name"],
            creation_nonce=row["creation_nonce"], logon_id=row["logon_id"],
            guardian_identity=_identity(_json(row["guardian_identity_json"])),
            wrapper_identity=None if row["wrapper_identity_json"] is None else _identity(_json(row["wrapper_identity_json"])))
    except (ValueError, TypeError, KeyError, RuntimeError):
        _fail("exclusion_invalid")
    _integer(row["schema_version"], 1, 1)
    _integer(row["registered_revision"], 1)
    values = binding._values()
    if not _same({key: row[key] for key in values}, values) or row["binding_sha256"] != hashlib.sha256(_canonical(values).encode()).hexdigest():
        _fail("exclusion_changed")
    return values


def _validate_completion(record):
    completion, kind = record["completion"], record["disposition"]
    demand = completion.get("demand") if type(completion) is dict else None
    _validate_demand(demand)
    if kind == "BEFORE_NATIVE":
        _shape(completion, {"schema_version", "disposition", "demand", "reservation_id", "daily_binding_sha256", "native_preparation"})
        if completion["native_preparation"] is not None:
            _fail("completion_invalid")
        digest = _digest("experiment-before-native-v1", completion)
    else:
        _shape(completion, {"schema_version", "disposition", "demand", "binding", "terminal", "scope_id",
            "isolated_ledger_path", "deadline_monotonic_ns", "acquisitions", "reservation_id", "daily_binding_sha256"})
        _uuid(completion["scope_id"])
        _integer(completion["deadline_monotonic_ns"], 1)
        _text(completion["isolated_ledger_path"], 32768)
        if Path(completion["isolated_ledger_path"]).parent != Path(demand["scope_directory"]):
            _fail("scope_path_changed")
        acquisitions = completion["acquisitions"]
        _shape(acquisitions, {"store", "launch", "mutex", "job"})
        allowed = {"not_entered", "entered", "returned", "known_absent", "failed_retained"}
        if any(type(value) is not str or value not in allowed for value in acquisitions.values()):
            _fail("acquisition_invalid")
        terminal, binding = completion["terminal"], completion["binding"]
        if kind in {"PREPARATION_CLOSED", "WRAPPER_NOT_CREATED"}:
            _shape(binding, {"experiment_id", "scope_id", "job_name", "creation_nonce", "guardian_identity",
                "command_sha256", "isolated_ledger_identity", "wrapper_creation"})
            if (binding["experiment_id"] != demand["experiment_id"] or binding["scope_id"] != completion["scope_id"] or
                    binding["command_sha256"] != demand["scope_sha256"] or binding["wrapper_creation"] != "never_created" or
                    not _same(binding["guardian_identity"], demand["caller_identity"]) or
                    type(binding["creation_nonce"]) is not str or re.fullmatch("[0-9a-f]{32}", binding["creation_nonce"]) is None or
                    binding["job_name"] != "Local\\ResourceSentinel.Test.Job." + binding["creation_nonce"]):
                _fail("completion_binding_changed")
            if binding["isolated_ledger_identity"] is not None:
                _file_identity(binding["isolated_ledger_identity"])
                if _same(binding["isolated_ledger_identity"], demand["ledger_identity"]):
                    _fail("isolated_ledger_not_distinct")
            if kind == "PREPARATION_CLOSED":
                _shape(terminal, {"state", "scope_id", "launch_sealed", "wrapper_created", "job_factory"})
                if (terminal["launch_sealed"] is not True or terminal["wrapper_created"] is not False or
                        terminal["job_factory"] != acquisitions["job"] or acquisitions["job"] not in {"not_entered", "failed_retained"} or
                        acquisitions["store"] not in {"not_entered", "entered", "returned"} or
                        acquisitions["launch"] not in {"not_entered", "returned"} or
                        acquisitions["mutex"] not in {"not_entered", "known_absent", "returned"}):
                    _fail("preparation_unsettled")
                # These are the actual original factory boundaries. An entered
                # later factory cannot coexist with an unfinished predecessor.
                if (acquisitions["store"] != "returned" and any(acquisitions[key] != "not_entered"
                        for key in ("launch", "mutex", "job")) or
                        acquisitions["launch"] != "returned" and any(acquisitions[key] != "not_entered"
                        for key in ("mutex", "job")) or
                        acquisitions["mutex"] != "returned" and acquisitions["job"] != "not_entered" or
                        acquisitions["launch"] == "returned" and binding["isolated_ledger_identity"] is None):
                    _fail("preparation_order_invalid")
            else:
                _shape(terminal, {"state", "scope_id", "launch_sealed", "root", "total_processes", "root_exit_code", "cpu_flags", "pending_intents"})
                if (terminal["launch_sealed"] is not True or terminal["root"] is not None or terminal["root_exit_code"] is not None or
                        any(type(terminal[key]) is not int or terminal[key] != 0 for key in ("total_processes", "cpu_flags", "pending_intents")) or
                        any(value != "returned" for value in acquisitions.values())):
                    _fail("wrapper_unsettled")
                _file_identity(binding["isolated_ledger_identity"])
        else:
            exclusion = record["preimage"]["exclusion"]
            if exclusion is None or not _same(binding, _exclusion_binding(exclusion)):
                _fail("completion_exclusion_changed")
            terminal_fields = set(_SCOPE_BINDING) | {"binding_sha256", "state", "revision", "launch_sealed", "root",
                "last_applied_cpu", "pending_target_cpu", "root_exit_code", "total_processes", "original_cpu"}
            _shape(terminal, terminal_fields)
            _integer(terminal["total_processes"], 0, (1 << 32) - 1)
            _identity(terminal["guardian_identity"])
            _identity(terminal["wrapper_identity"])
            try:
                scope_binding = _scope_binding({key: terminal[key] for key in _SCOPE_BINDING})
                ScopeJournal._validate_row(terminal)
            except (ValueError, TypeError, RuntimeError):
                _fail("terminal_invalid")
            if (terminal["binding_sha256"] != hashlib.sha256(_canonical(scope_binding).encode()).hexdigest() or
                    not _same(terminal["original_cpu"], {"flags": 0, "rate_bp": 0}) or
                    terminal["pending_target_cpu"] is not None or
                    terminal["last_applied_cpu"] is not None and not _same(terminal["last_applied_cpu"], {"flags": 0, "rate_bp": 0}) or
                    any(value != "returned" for value in acquisitions.values())):
                _fail("terminal_unsettled")
            expected = dict(experiment_id=demand["experiment_id"], scope_id=completion["scope_id"],
                daily_execution_id=demand["execution_id"], reservation_id=record["reservation_id"],
                command_sha256=demand["scope_sha256"], deadline_monotonic_ns=completion["deadline_monotonic_ns"],
                **demand["generation"])
            expected["source_generation"] = expected.pop("generation")
            if (not _same({key: terminal[key] for key in expected}, expected) or
                    not _same(terminal["guardian_identity"], demand["caller_identity"]) or
                    binding["isolated_ledger_path"] != completion["isolated_ledger_path"] or
                    binding["scope_execution_id"] != completion["scope_id"] or
                    _same(terminal["isolated_ledger_identity"], demand["ledger_identity"])):
                _fail("terminal_binding_changed")
            for target, source in (("job_name", "job_name"), ("creation_nonce", "creation_nonce"),
                    ("isolated_ledger_identity", "isolated_ledger_identity_json"),
                    ("guardian_identity", "guardian_identity_json"), ("wrapper_identity", "wrapper_identity_json")):
                value = _json(binding[source]) if source.endswith("_json") else binding[source]
                if not _same(terminal[target], value):
                    _fail("terminal_binding_changed")
            if kind == "FINISHED":
                root = _identity(terminal["root"])
                if root.logon_id != demand["caller_identity"]["logon_id"] or root.pid in (terminal["guardian_identity"]["pid"], terminal["wrapper_identity"]["pid"]):
                    _fail("terminal_binding_changed")
        if terminal["state"] != kind or terminal["scope_id"] != completion["scope_id"]:
            _fail("completion_invalid")
        digest = hashlib.sha256(_canonical(completion).encode()).hexdigest()
    if (type(completion["schema_version"]) is not int or completion["schema_version"] != 1 or
            completion["disposition"] != kind or digest != record["completion_digest"]):
        _fail("completion_digest_changed")
    if kind != "PREPARATION_CLOSED" or completion["reservation_id"] is not None:
        if completion["reservation_id"] != record["reservation_id"] or completion["daily_binding_sha256"] != record["demand_binding_sha256"]:
            _fail("completion_daily_binding_changed")
    elif completion["daily_binding_sha256"] is not None:
        _fail("completion_daily_binding_changed")
    return demand


def canonical_receipt(record):
    """Validate a complete data record and return canonical JSON plus its digest."""
    _shape(record, _RECORD_FIELDS)
    if (type(record["schema_version"]) is not int or record["schema_version"] != 1 or
            type(record["disposition"]) is not str or record["disposition"] not in DISPOSITIONS):
        _fail("version_invalid")
    for key in ("receipt_id", "operation_id", "experiment_id", "execution_id"):
        _uuid(record[key])
    for key in ("reservation_id", "request_key"):
        _text(record[key])
    for key in ("demand_binding_sha256", "completion_digest", "cleanup_digest", "preimage_sha256", "postimage_sha256"):
        _hash(record[key])
    policy, pre, post = record["policy"], record["preimage"], record["postimage"]
    _shape(policy, {"instance_id", "logon_id"})
    _uuid(policy["instance_id"])
    _shape(pre, {"managed", "allocation", "queue", "exclusion", "registry_revision"})
    _shape(post, {"managed", "archive", "exclusion", "registry_revision"})
    _integer(pre["registry_revision"], 0, (1 << 63) - 2)
    _integer(post["registry_revision"], 1)
    now = record["transaction_time"]
    if type(now) is not float:
        _fail("transaction_time_invalid")
    _number(now)
    demand = _validate_completion(record)
    if (any(record[key] != demand[key] for key in ("experiment_id", "execution_id", "request_key", "suite")) or
            policy["logon_id"] != demand["caller_identity"]["logon_id"] or
            _metadata(demand, record["reservation_id"])["binding_sha256"] != record["demand_binding_sha256"]):
        _fail("demand_binding_changed")
    expected_cleanup = cleanup_digest(receipt_id=record["receipt_id"], operation_id=record["operation_id"],
        reservation_id=record["reservation_id"], demand_binding_sha256=record["demand_binding_sha256"],
        completion_digest=record["completion_digest"], demand=demand)
    if record["cleanup_digest"] != expected_cleanup:
        _fail("cleanup_digest_changed")
    _validate_managed(pre["managed"], demand, record["reservation_id"])
    _validate_allocation(pre["allocation"], demand, record["reservation_id"])
    _validate_queue(pre["queue"], pre["allocation"], demand)
    if (now < pre["allocation"]["created_at"] or now < pre["managed"]["created_at"] or
            pre["managed"]["state"] == "UNCERTAIN_HOLD" and now < pre["allocation"]["expires_at"] or
            not _same(post["managed"], cancellation_image(pre["managed"], now)) or
            not _same(post["archive"], archive_image(pre["allocation"], now)) or
            post["registry_revision"] != pre["registry_revision"] + 1):
        _fail("postimage_invalid")
    if pre["exclusion"] is None:
        if post["exclusion"] is not None or record["disposition"] not in {"BEFORE_NATIVE", "PREPARATION_CLOSED", "WRAPPER_NOT_CREATED"}:
            _fail("exclusion_disposition_invalid")
    else:
        values = _exclusion_binding(pre["exclusion"])
        if (record["disposition"] not in {"NEVER_LAUNCHED", "FINISHED"} or pre["exclusion"]["phase"] != "REGISTERED" or
                pre["exclusion"]["cleanup_digest"] is not None or
                pre["exclusion"]["registered_revision"] > pre["registry_revision"] or
                not _same(post["exclusion"], pre["exclusion"] | dict(phase="CLOSED", cleanup_digest=expected_cleanup)) or
                values["experiment_id"] != record["experiment_id"] or values["daily_execution_id"] != record["execution_id"] or
                values["reservation_id"] != record["reservation_id"] or values["source_generation"] != demand["generation"]["generation"] or
                values["isolated_policy_instance_id"] == policy["instance_id"]):
            _fail("exclusion_postimage_invalid")
    if record["preimage_sha256"] != image_digest("preimage", pre) or record["postimage_sha256"] != image_digest("postimage", post):
        _fail("image_digest_changed")
    encoded = _canonical(record)
    if len(encoded.encode("ascii")) > MAX_RECEIPT_BYTES:
        _fail("receipt_bound")
    return encoded, _digest("experiment-cleanup-receipt-v1", record)


def _transaction(conn):
    if not conn.in_transaction:
        _fail("transaction_required")


def _sql(value):
    return " ".join(value.split()).rstrip(";") if type(value) is str else None


def _schema_definition(conn, table, statement, fields, guards):
    names = (table, *guards)
    rows = conn.execute("""SELECT name,type,
        CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END
        FROM sqlite_master WHERE name IN (""" + ",".join("?" for _ in names) +
        ") OR (type='trigger' AND tbl_name=?) LIMIT 65", (*names, table)).fetchall()
    if not rows:
        return False
    expected = {table: ("table", _sql(statement)), **{key: ("trigger", _sql(value)) for key, value in guards.items()}}
    if ({row[0]: (row[1], _sql(row[2])) for row in rows} != expected or
            set(row[1] for row in conn.execute("PRAGMA table_info(" + table + ")")) != set(fields)):
        _fail("schema_invalid")
    return True


def schema_locked(conn, *, create=False):
    """Validate only; the original release operation owns schema installation."""
    _transaction(conn)
    if create:
        _fail("original_schema_installer_required")
    return _schema_definition(conn, TABLE, TABLE_SQL, FIELDS, TRIGGER_SQL)


class _Budget:
    def __init__(self, maximum):
        _integer(maximum, 0, MAX_BYTES)
        self.maximum, self.bytes, self.rows = maximum, 0, 0
        self.observed = []

    def add(self, value):
        safe = {key: ({"blob_sha256": hashlib.sha256(item).hexdigest()} if type(item) is bytes else item)
                for key, item in value.items()}
        self.bytes += len(_canonical(safe).encode("ascii"))
        self.rows += 1
        if self.bytes > self.maximum:
            _fail("bytes_exceeded")


def _rows(conn, table, fields, budget, *, where="", parameters=(), limit=MAX_HISTORY):
    # All table/column/predicate inputs are private fixed strings in this module.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(" + table + ")")}
    if (not set(fields) <= columns or table != "adaptive_runtime" and set(fields) != columns):
        _fail("row_schema_invalid")
    bounded = " AND ".join("(" + name + " IS NULL OR length(CAST(" + name + " AS BLOB))<=" +
        str(MAX_RECEIPT_BYTES if table == TABLE and name == "receipt_json" else MAX_CELL_BYTES) + ")" for name in fields)
    projection = ",".join("CASE WHEN " + bounded + " THEN " + name + " END" for name in fields)
    cursor = conn.execute("SELECT " + projection + ",CASE WHEN " + bounded + " THEN 1 ELSE 0 END FROM " + table +
        (" WHERE " + where if where else "") + " ORDER BY rowid LIMIT ?", (*parameters, limit + 1))
    result = []
    for values in cursor:
        if len(result) >= limit:
            _fail("history_exceeded")
        if values[-1] != 1:
            _fail("cell_exceeded")
        row = dict(zip(fields, tuple(values)[:-1]))
        budget.add(row)
        budget.observed.append(_ObservedRow(table, tuple(fields), tuple(values)[:-1]))
        result.append(row)
    return result


def _one(conn, table, fields, budget, where, parameters):
    rows = _rows(conn, table, fields, budget, where=where, parameters=parameters, limit=2)
    if len(rows) != 1:
        _fail("tuple_missing_or_duplicate")
    return rows[0]


def _no_obligation(conn, execution_id, reservation_id, request_key, task_id):
    predicates = (("reservations", "id=? OR execution_id=? OR request_key=?", (reservation_id, execution_id, request_key)),
        ("worker_reservations", "execution_id=? OR task_id=?", (execution_id, task_id)),
        ("queue", "request_key=? OR managed_execution_id=?", (request_key, execution_id)),
        ("managed_executions", "parent_execution_id=?", (execution_id,)))
    for table, where, args in predicates:
        if conn.execute("SELECT 1 FROM " + table + " WHERE " + where + " LIMIT 1", args).fetchone():
            _fail("obligation_remaining")
    _no_daily_native_history(conn, execution_id)


def _no_daily_native_history(conn, execution_id):
    # This daily claim was never exported. A production launch/control/terminal
    # record cannot be made harmless by an isolated experiment completion.
    for table in ("adaptive_control_slot", "adaptive_actions", "adaptive_launch_requests", "adaptive_launch_fences",
            "adaptive_retirement_requests", "adaptive_prelaunch_retirements", "adaptive_terminal_custody_receipts",
            "adaptive_prelaunch_custody_receipts", "adaptive_barrier_clears"):
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'", (table,)).fetchone():
            if conn.execute("SELECT 1 FROM " + table + " WHERE execution_id=? LIMIT 1", (execution_id,)).fetchone():
                _fail("daily_native_history_present")


def _active_demand(metadata):
    """Validate unresolved immutable metadata without pretending it is completion."""
    _shape(metadata, experiment_demand._FIELDS)
    for key in ("experiment_id", "execution_id", "source_generation"):
        _uuid(metadata[key])
    for key in ("scope_sha256", "source_digest", "config_digest", "spec_hash", "admission_binding_hash", "binding_sha256"):
        _hash(metadata[key])
    _text(metadata["reservation_id"])
    _text(metadata["request_key"])
    _text(metadata["scope_directory"], 32768)
    if (not Path(metadata["scope_directory"]).is_absolute() or ".." in Path(metadata["scope_directory"]).parts or
            metadata["suite"] not in {"S1", "S2", "S3", "P4", "P5", "P6"} or
            metadata["state"] != "ADMITTED"):
        _fail("unresolved_metadata_invalid")
    _integer(metadata["schema_version"], 1, 1)
    _integer(metadata["revision"], 0, 0)
    for key in ("scope_identity_json", "ledger_identity_json"):
        _file_identity(_json(metadata[key]))
    caller = dict(pid=metadata["owner_pid"], created_filetime_100ns=metadata["owner_birth"], logon_id=metadata["owner_logon_id"])
    _identity(caller)
    requested = _json(metadata["demand_json"])
    _resources(requested)
    bare = {key: value for key, value in metadata.items() if key != "binding_sha256"}
    if metadata["binding_sha256"] != hashlib.sha256(_canonical(bare).encode()).hexdigest():
        _fail("unresolved_metadata_invalid")
    return dict(execution_id=metadata["execution_id"], request_key=metadata["request_key"],
        caller_identity=caller, requested=requested, spec_hash=metadata["spec_hash"],
        admission_binding_hash=metadata["admission_binding_hash"])


@dataclass(frozen=True, repr=False)
class _ObservedRow:
    """Private exact bounded SQL observation, never serialized as a receipt.

    In particular, credential bytes must not enter diagnostics or public JSON.
    Retirement consumes these originals instead of reconstructing postimages.
    """
    table: str
    fields: tuple[str, ...]
    values: tuple


@dataclass(frozen=True, repr=False)
class ExperimentHistory:
    """Immutable observations; JSON values are decoded into fresh copies by callers."""
    completed_execution_ids: frozenset[str]
    active_experiment_ids: frozenset[str]
    receipts_json: tuple[str, ...]
    active_json: tuple[str, ...]
    archives_json: tuple[str, ...]
    exclusions_json: tuple[str, ...]
    rows_used: int
    bytes_used: int
    digest: str
    _sql_rows: tuple[_ObservedRow, ...]


def verify_experiment_history_locked(conn, *, max_bytes=MAX_BYTES):
    """Validate complete history on this snapshot; caller owns native POLICY.

    max_bytes may only reduce the fixed budget, allowing retirement to pass its
    remaining aggregate allowance. Return bytes_used must be charged once to
    that parent inventory. No existence query or returned ID is native authority.
    """
    _transaction(conn)
    budget = _Budget(max_bytes)
    receipt_schema = schema_locked(conn)
    demand_schema = _schema_definition(conn, experiment_demand.TABLE, experiment_demand._TABLE_SQL,
        experiment_demand._FIELDS, experiment_demand._TRIGGER_SQL)
    exclusion_schema = _schema_definition(conn, experiment_exclusion.TABLE, experiment_exclusion._SCHEMA,
        experiment_exclusion._FIELDS, experiment_exclusion._GUARDS)
    demands = _rows(conn, experiment_demand.TABLE, experiment_demand._FIELDS, budget) if demand_schema else []
    receipts = _rows(conn, TABLE, FIELDS, budget) if receipt_schema else []
    exclusions = _rows(conn, experiment_exclusion.TABLE, experiment_exclusion._FIELDS, budget) if exclusion_schema else []
    if (receipts or exclusions) and not demands:
        _fail("orphan_history")
    by_experiment = {row["experiment_id"]: row for row in demands}
    by_receipt = {row["experiment_id"]: row for row in receipts}
    by_exclusion = {row["experiment_id"]: row for row in exclusions}
    if (len(by_experiment) != len(demands) or len(by_receipt) != len(receipts) or len(by_exclusion) != len(exclusions) or
            not set(by_receipt) <= set(by_experiment) or not set(by_exclusion) <= set(by_experiment)):
        _fail("orphan_or_duplicate_history")
    completed, active, records, archives = [], [], [], []
    runtime = _one(conn, "adaptive_runtime", ("registry_revision",), budget, "singleton=1", ())
    _integer(runtime["registry_revision"])
    for experiment_id, metadata in by_experiment.items():
        _uuid(experiment_id)
        _uuid(metadata["execution_id"])
        _text(metadata["reservation_id"])
        _text(metadata["request_key"])
        managed = _one(conn, "managed_executions", MANAGED_FIELDS, budget,
            "execution_id=? OR (reservation_id=? AND (allocation_kind='direct' OR allocation_kind IS NULL OR "
            "allocation_kind NOT IN ('direct','routed')))", (metadata["execution_id"], metadata["reservation_id"]))
        receipt = by_receipt.get(experiment_id)
        exclusion = by_exclusion.get(experiment_id)
        if receipt is None:
            # No receipt can resolve this obligation. Validate the immutable
            # admission data and keep even a damaged/missing allocation closed.
            demand = _active_demand(metadata)
            _validate_managed(managed_image(managed), demand, metadata["reservation_id"])
            allocation = _one(conn, "reservations", ALLOCATION_FIELDS, budget,
                "id=? OR execution_id=? OR request_key=?", (metadata["reservation_id"], metadata["execution_id"], metadata["request_key"]))
            _validate_allocation(allocation, demand, metadata["reservation_id"])
            queued = _rows(conn, "queue", QUEUE_FIELDS, budget,
                where="request_key=? OR managed_execution_id=?", parameters=(metadata["request_key"], metadata["execution_id"]), limit=1)
            _validate_queue(queued[0] if queued else None, allocation, demand)
            if (conn.execute("SELECT 1 FROM executions WHERE reservation_id=? OR request_key=? LIMIT 1",
                    (metadata["reservation_id"], metadata["request_key"])).fetchone() or
                    conn.execute("SELECT 1 FROM worker_reservations WHERE execution_id=? OR task_id=? LIMIT 1",
                        (metadata["execution_id"], managed["task_id"])).fetchone() or
                    conn.execute("SELECT 1 FROM managed_executions WHERE parent_execution_id=? LIMIT 1", (metadata["execution_id"],)).fetchone()):
                _fail("unresolved_obligation_conflict")
            _no_daily_native_history(conn, metadata["execution_id"])
            if exclusion is not None:
                values = _exclusion_binding(exclusion)
                if (exclusion["phase"] != "REGISTERED" or exclusion["cleanup_digest"] is not None or
                        values["daily_execution_id"] != metadata["execution_id"] or values["reservation_id"] != metadata["reservation_id"] or
                        values["source_generation"] != metadata["source_generation"] or
                        values["guardian_identity_json"] != _canonical(demand["caller_identity"]) or
                        Path(values["isolated_ledger_path"]).parent != Path(metadata["scope_directory"]) or
                        values["isolated_ledger_identity_json"] == metadata["ledger_identity_json"] or
                        exclusion["registered_revision"] > runtime["registry_revision"]):
                    _fail("unresolved_exclusion_invalid")
            active.append(_canonical(metadata))
            continue
        record = _json(receipt["receipt_json"], MAX_RECEIPT_BYTES)
        encoded, digest = canonical_receipt(record)
        expected_columns = {key: record[key] for key in FIELDS if key not in {"receipt_json", "receipt_sha256"}}
        expected_columns.update(receipt_json=encoded, receipt_sha256=digest)
        if not _same(receipt, expected_columns):
            _fail("receipt_binding_changed")
        expected_metadata = _metadata(record["completion"]["demand"], record["reservation_id"])
        if (not _same(metadata, expected_metadata) or not _same(managed_image(managed), record["postimage"]["managed"]) or
                record["postimage"]["registry_revision"] > runtime["registry_revision"] or
                not _same(exclusion, record["postimage"]["exclusion"])):
            _fail("committed_tuple_changed")
        archive = _one(conn, "executions", ("id", *ARCHIVE_FIELDS), budget,
            "reservation_id=? OR request_key=?", (record["reservation_id"], record["request_key"]))
        _integer(archive["id"], 1)
        if not _same({key: archive[key] for key in ARCHIVE_FIELDS}, record["postimage"]["archive"]):
            _fail("archive_changed")
        _no_obligation(conn, record["execution_id"], record["reservation_id"], record["request_key"], managed["task_id"])
        completed.append(record["execution_id"])
        records.append(encoded)
        archives.append(_canonical(archive))
    if len(active) > experiment_exclusion.MAX_SCOPES:
        _fail("active_scope_bound")
    observed = dict(receipts=records, active=active, archives=archives, exclusions=exclusions)
    return ExperimentHistory(frozenset(completed), frozenset(json.loads(value)["experiment_id"] for value in active),
        tuple(records), tuple(active), tuple(archives), tuple(_canonical(value) for value in exclusions),
        budget.rows, budget.bytes, _digest("experiment-history-v1", observed), tuple(budget.observed))
