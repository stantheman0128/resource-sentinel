"""Read-only test diagnostics, never Job enrollment or control eligibility.

QueryInformationJobObject(NULL) describes only the calling process's immediate
Job. Its ancestors and effective inherited limits remain unknown. Process parent
lineage is a different relationship. No function launches or modifies a process.
Deadlines are checked around synchronous calls, not an OS hard lifetime bound.

ABI references: Microsoft Learn QueryInformationJobObject, GROUP_AFFINITY,
JOBOBJECT_EXTENDED_LIMIT_INFORMATION and NtQueryInformationProcess.
"""
from __future__ import annotations

import copy
import ctypes as c
import math
import os
import re
import time


U16, U32, I32, U64, I64 = c.c_uint16, c.c_uint32, c.c_int32, c.c_uint64, c.c_int64
MAX_HOPS = 6
MAX_GROUPS = 64
PUBLIC_FIELDS = ("pid", "creation_filetime", "session_id", "in_any_job", "elevated", "integrity_rid")
MATCH_FIELDS = {"same_user": "user_sid", "same_logon": "logon_sid",
                "same_authentication": "authentication_luid", "same_session": "session_id"}
QUERY_NAMES = ("cpu", "extended_limits", "ui_restrictions", "groups", "group_affinity")
ERROR_STAGES = frozenset({
    "unsupported_platform_or_bitness", "native_binding_unavailable", "invalid_deadline", "deadline_elapsed",
    "self_identity_invalid", "self_read", "self_identity_changed", "job_state_unknown",
    "parent_relation_query", "parent_relation_size", "parent_relation_pid_mismatch", "parent_pid_invalid",
    "parent_cycle", "parent_open", "parent_read", "parent_identity_changed", "parent_relation_changed",
    "parent_birth_not_before_child", "parent_security_boundary", "parent_close", "unexpected_diagnostic_error",
    *{f"job_{name}_{suffix}" for name in QUERY_NAMES for suffix in ("query", "size", "invalid")},
})
STOP_REASONS = frozenset(("not_started", "parent_absent", "hop_limit", "deadline", "security_boundary", "unknown"))


class DiagnosticError(Exception):
    def __init__(self, stage, code=None, domain=None):
        self.stage, self.code, self.domain = stage, code, domain
        super().__init__(stage)


class CpuInformation(c.Structure):
    _fields_ = [("ControlFlags", U32), ("RateUnion", U32)]


class BasicLimits(c.Structure):
    _fields_ = [("PerProcessUserTimeLimit", I64), ("PerJobUserTimeLimit", I64),
                ("LimitFlags", U32), ("MinimumWorkingSetSize", U64), ("MaximumWorkingSetSize", U64),
                ("ActiveProcessLimit", U32), ("Affinity", U64), ("PriorityClass", U32), ("SchedulingClass", U32)]


class IoCounters(c.Structure):
    _fields_ = [(name, U64) for name in ("ReadOperations", "WriteOperations", "OtherOperations",
                                       "ReadBytes", "WriteBytes", "OtherBytes")]


class ExtendedLimits(c.Structure):
    _fields_ = [("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", U64), ("JobMemoryLimit", U64),
                ("PeakProcessMemoryUsed", U64), ("PeakJobMemoryUsed", U64)]


class UiRestrictions(c.Structure):
    _fields_ = [("UIRestrictionsClass", U32)]


class GroupAffinity(c.Structure):
    _fields_ = [("Mask", U64), ("Group", U16), ("Reserved", U16 * 3)]


class ProcessBasicInformation(c.Structure):
    _fields_ = [("ExitStatus", I32), ("PebBaseAddress", U64), ("AffinityMask", U64),
                ("BasePriority", I32), ("UniqueProcessId", U64), ("InheritedFromUniqueProcessId", U64)]


LIMIT_FIELDS = {
    "per_process_user_time_limit_100ns": ("PerProcessUserTimeLimit", -2**63, 2**63 - 1),
    "per_job_user_time_limit_100ns": ("PerJobUserTimeLimit", -2**63, 2**63 - 1),
    "limit_flags": ("LimitFlags", 0, 2**32 - 1),
    "minimum_working_set_bytes": ("MinimumWorkingSetSize", 0, 2**64 - 1),
    "maximum_working_set_bytes": ("MaximumWorkingSetSize", 0, 2**64 - 1),
    "active_process_limit": ("ActiveProcessLimit", 0, 2**32 - 1),
    "affinity_mask": ("Affinity", 0, 2**64 - 1),
    "priority_class": ("PriorityClass", 0, 2**32 - 1),
    "scheduling_class": ("SchedulingClass", 0, 2**32 - 1),
}
MEMORY_FIELDS = {"process_memory_limit_bytes": "ProcessMemoryLimit", "job_memory_limit_bytes": "JobMemoryLimit",
                 "peak_process_memory_bytes": "PeakProcessMemoryUsed", "peak_job_memory_bytes": "PeakJobMemoryUsed"}


class NativeDiagnostics:
    """Only binds query functions; every Job query explicitly uses NULL."""

    def __init__(self, kernel):
        if os.name != "nt" or c.sizeof(c.c_void_p) != 8:
            raise DiagnosticError("unsupported_platform_or_bitness")
        self.query = kernel.QueryInformationJobObject
        self.query.argtypes = (c.c_void_p, I32, c.c_void_p, U32, c.POINTER(U32))
        self.query.restype = I32
        self.ntdll = c.WinDLL("ntdll", use_last_error=True)
        self.parent_query = self.ntdll.NtQueryInformationProcess
        self.parent_query.argtypes = (c.c_void_p, I32, c.c_void_p, U32, c.POINTER(U32))
        self.parent_query.restype = I32

    def _job(self, name, information_class, buffer, item_size=None):
        written = U32()
        if not self.query(None, information_class, c.byref(buffer), c.sizeof(buffer), c.byref(written)):
            raise DiagnosticError(f"job_{name}_query", c.get_last_error(), "win32")
        size = int(written.value)
        if item_size is None:
            valid = size == c.sizeof(buffer)
        else:
            valid = size <= c.sizeof(buffer) and size % item_size == 0
        if not valid:
            raise DiagnosticError(f"job_{name}_size")
        return size

    def job_query(self, name):
        if name == "cpu":
            value = CpuInformation()
            self._job(name, 15, value)
            # These are raw union views. ControlFlags chooses their meaning;
            # ancestor CPU restrictions and effective capacity remain unknown.
            return dict(control_flags=int(value.ControlFlags), cpu_rate_or_weight_raw=int(value.RateUnion),
                        min_rate_raw=int(value.RateUnion & 0xFFFF), max_rate_raw=int(value.RateUnion >> 16))
        if name == "extended_limits":
            value = ExtendedLimits()
            self._job(name, 9, value)
            result = {key: int(getattr(value.BasicLimitInformation, spec[0])) for key, spec in LIMIT_FIELDS.items()}
            result.update({key: int(getattr(value, source)) for key, source in MEMORY_FIELDS.items()})
            return result
        if name == "ui_restrictions":
            value = UiRestrictions()
            self._job(name, 4, value)
            return {"restriction_flags": int(value.UIRestrictionsClass)}
        if name == "groups":
            value = (U16 * MAX_GROUPS)()
            size = self._job(name, 11, value, c.sizeof(U16))
            return [int(value[index]) for index in range(size // c.sizeof(U16))]
        if name == "group_affinity":
            value = (GroupAffinity * MAX_GROUPS)()
            size = self._job(name, 14, value, c.sizeof(GroupAffinity))
            result = []
            for row in value[:size // c.sizeof(GroupAffinity)]:
                if any(row.Reserved):
                    raise DiagnosticError("job_group_affinity_invalid")
                result.append({"group": int(row.Group), "affinity_mask": int(row.Mask)})
            return result
        raise DiagnosticError("unexpected_diagnostic_error")

    def parent_pid(self, handle, expected_pid):
        value, written = ProcessBasicInformation(), U32()
        status = self.parent_query(handle, 0, c.byref(value), c.sizeof(value), c.byref(written))
        if status != 0:
            raise DiagnosticError("parent_relation_query", int(status) & 0xFFFFFFFF, "ntstatus")
        if written.value != c.sizeof(value):
            raise DiagnosticError("parent_relation_size")
        if value.UniqueProcessId != expected_pid:
            raise DiagnosticError("parent_relation_pid_mismatch")
        if value.InheritedFromUniqueProcessId > 0xFFFFFFFF:
            raise DiagnosticError("parent_pid_invalid")
        return int(value.InheritedFromUniqueProcessId)


def _error(error, fallback="unexpected_diagnostic_error"):
    stage, code, domain = fallback, None, None
    if isinstance(error, DiagnosticError):
        stage, code, domain = error.stage, error.code, error.domain
    elif type(getattr(error, "win32_error", None)) is int:
        code, domain = error.win32_error, "win32"
    if type(stage) is not str or stage not in ERROR_STAGES:
        stage = "unexpected_diagnostic_error"
    if type(code) is not int or not 0 <= code <= 0xFFFFFFFF or domain not in ("win32", "ntstatus"):
        code = domain = None
    return {"stage": stage, "code_domain": domain, "code": code}


def _deadline(clock, deadline):
    now = clock()
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or type(now) not in (int, float) or not math.isfinite(now):
        raise DiagnosticError("invalid_deadline")
    if now >= deadline:
        raise DiagnosticError("deadline_elapsed")


def _public(observation):
    result = {name: observation[name] for name in PUBLIC_FIELDS}
    _validate_process(result)
    return result


def _unknown(stage):
    return {"status": "unknown", "value": None, "error": _error(DiagnosticError(stage))}


def _lineage(api, native, self_handle, observation, clock, deadline):
    result = dict(semantics="process_ancestry_not_job_hierarchy", max_hops=MAX_HOPS,
                  validity="unknown", stop_reason="not_started", parents=[], errors=[])
    opened = []
    handle, current = self_handle, observation
    seen = {current["pid"]}
    stage = "parent_read"
    try:
        for _hop in range(MAX_HOPS):
            _deadline(clock, deadline)
            stage = "parent_read"
            if api.read_process(handle, current["pid"]) != current:
                raise DiagnosticError("parent_identity_changed")
            _deadline(clock, deadline)
            stage = "parent_relation_query"
            parent_pid = native.parent_pid(handle, current["pid"])
            _deadline(clock, deadline)
            if type(parent_pid) is not int or not 0 <= parent_pid <= 0xFFFFFFFF:
                raise DiagnosticError("parent_pid_invalid")
            if parent_pid == 0:
                result.update(validity="verified_prefix", stop_reason="parent_absent")
                break
            if parent_pid in seen:
                raise DiagnosticError("parent_cycle")
            stage = "parent_open"
            parent_handle = api.open_process(parent_pid)
            opened.append(parent_handle)
            _deadline(clock, deadline)
            stage = "parent_read"
            parent = api.read_process(parent_handle, parent_pid)
            _deadline(clock, deadline)
            public = _public(parent)
            if public["pid"] != parent_pid:
                raise DiagnosticError("parent_identity_changed")
            if api.read_process(parent_handle, parent_pid) != parent:
                raise DiagnosticError("parent_identity_changed")
            _deadline(clock, deadline)
            stage = "parent_relation_query"
            if native.parent_pid(handle, current["pid"]) != parent_pid:
                raise DiagnosticError("parent_relation_changed")
            _deadline(clock, deadline)
            stage = "parent_read"
            if api.read_process(handle, current["pid"]) != current:
                raise DiagnosticError("parent_identity_changed")
            _deadline(clock, deadline)
            # Equal timestamps cannot prove this opened PID is the historical
            # parent; preserve unknown rather than accepting a coarse tie.
            if int(public["creation_filetime"]) >= int(current["creation_filetime"]):
                raise DiagnosticError("parent_birth_not_before_child")
            matches = {name: parent[key] == observation[key] for name, key in MATCH_FIELDS.items()}
            result["parents"].append(dict(process=public, matches=matches, relation_rechecked=True,
                                          creation_not_after_child=True))
            if not all(matches.values()):
                result["stop_reason"] = "security_boundary"
                raise DiagnosticError("parent_security_boundary")
            seen.add(parent_pid)
            handle, current = parent_handle, parent
        else:
            result.update(validity="verified_prefix", stop_reason="hop_limit")
    except Exception as error:
        result["validity"] = "unknown"
        if isinstance(error, DiagnosticError) and error.stage == "deadline_elapsed":
            result["stop_reason"] = "deadline"
        elif result["stop_reason"] != "security_boundary":
            result["stop_reason"] = "unknown"
        result["errors"].append(_error(error, stage))
    finally:
        # Never close the caller-owned self handle. Every acquired ancestor is
        # held until collection finishes; failed cleanup does not hide failures.
        for parent_handle in reversed(opened):
            try:
                api.close(parent_handle)
            except Exception as error:
                result["validity"] = "unknown"
                if result["stop_reason"] != "security_boundary":
                    result["stop_reason"] = "unknown"
                result["errors"].append(_error(error, "parent_close"))
    return result


def collect_diagnostics(api, self_handle, self_observation, *, clock=time.monotonic, deadline, native=None):
    report = dict(schema_version=1, self=None, self_rechecked=False,
                  ancestor_job_hierarchy="unknown", effective_inherited_limits="unknown",
                  control_eligibility="not_assessed", process_control_writes=0,
                  immediate_job={"scope": "current_process_immediate_job_only", "snapshot_atomic": False,
                                 "membership": "unknown", "queries": {name: _unknown("job_state_unknown") for name in QUERY_NAMES}},
                  lineage=dict(semantics="process_ancestry_not_job_hierarchy", max_hops=MAX_HOPS,
                               validity="unknown", stop_reason="not_started", parents=[], errors=[]), errors=[])
    stage = "self_identity_invalid"
    try:
        report["self"] = _public(self_observation)
        if self_observation["pid"] != os.getpid():
            raise DiagnosticError("self_identity_invalid")
        _deadline(clock, deadline)
        stage = "self_read"
        if api.read_process(self_handle, self_observation["pid"]) != self_observation:
            raise DiagnosticError("self_identity_changed")
        _deadline(clock, deadline)
        stage = "native_binding_unavailable"
        native = NativeDiagnostics(api.kernel) if native is None else native
        _deadline(clock, deadline)
        in_job = self_observation["in_any_job"]
        report["immediate_job"]["membership"] = "present" if in_job else "absent"
        for name in QUERY_NAMES:
            if not in_job:
                report["immediate_job"]["queries"][name] = {"status": "not_applicable", "value": None, "error": None}
                continue
            try:
                _deadline(clock, deadline)
                value = native.job_query(name)
                _deadline(clock, deadline)
                _validate_value(name, value)
                report["immediate_job"]["queries"][name] = {"status": "valid", "value": value, "error": None}
            except Exception as error:
                report["immediate_job"]["queries"][name] = {"status": "unknown", "value": None,
                                                            "error": _error(error, f"job_{name}_query")}
        report["lineage"] = _lineage(api, native, self_handle, self_observation, clock, deadline)
        _deadline(clock, deadline)
        stage = "self_read"
        if api.read_process(self_handle, self_observation["pid"]) != self_observation:
            raise DiagnosticError("self_identity_changed")
        _deadline(clock, deadline)
        report["self_rechecked"] = True
    except Exception as error:
        report["errors"].append(_error(error, stage))
        if report["lineage"]["validity"] == "verified_prefix":
            report["lineage"].update(validity="unknown", stop_reason="unknown")
    return sanitize_diagnostics(report)


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("diagnostic_schema_invalid")


def _integer(value, low=0, high=0xFFFFFFFF):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("diagnostic_integer_invalid")


def _validate_process(value):
    _keys(value, PUBLIC_FIELDS)
    _integer(value["pid"], 1)
    _integer(value["session_id"])
    _integer(value["integrity_rid"])
    birth = value["creation_filetime"]
    if type(birth) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}", birth) or int(birth) > 2**64 - 1:
        raise ValueError("diagnostic_birth_invalid")
    if any(type(value[name]) is not bool for name in ("in_any_job", "elevated")):
        raise ValueError("diagnostic_boolean_invalid")


def _validate_error(value):
    _keys(value, ("stage", "code_domain", "code"))
    if type(value["stage"]) is not str or value["stage"] not in ERROR_STAGES:
        raise ValueError("diagnostic_error_stage_invalid")
    if value["code_domain"] is None:
        if value["code"] is not None:
            raise ValueError("diagnostic_error_code_invalid")
    elif value["code_domain"] in ("win32", "ntstatus"):
        _integer(value["code"])
    else:
        raise ValueError("diagnostic_error_domain_invalid")


def _errors(values, maximum):
    if type(values) is not list or len(values) > maximum:
        raise ValueError("diagnostic_errors_invalid")
    for value in values:
        _validate_error(value)


def _validate_value(name, value):
    if name == "cpu":
        _keys(value, ("control_flags", "cpu_rate_or_weight_raw", "min_rate_raw", "max_rate_raw"))
        _integer(value["control_flags"])
        _integer(value["cpu_rate_or_weight_raw"])
        for field in ("min_rate_raw", "max_rate_raw"):
            _integer(value[field], 0, 0xFFFF)
        raw = value["cpu_rate_or_weight_raw"]
        if value["min_rate_raw"] != raw & 0xFFFF or value["max_rate_raw"] != raw >> 16:
            raise ValueError("diagnostic_cpu_union_invalid")
    elif name == "extended_limits":
        _keys(value, (*LIMIT_FIELDS, *MEMORY_FIELDS))
        for field, (_source, low, high) in LIMIT_FIELDS.items():
            _integer(value[field], low, high)
        for field in MEMORY_FIELDS:
            _integer(value[field], 0, 2**64 - 1)
    elif name == "ui_restrictions":
        _keys(value, ("restriction_flags",))
        _integer(value["restriction_flags"])
    elif name in ("groups", "group_affinity"):
        if type(value) is not list or len(value) > MAX_GROUPS:
            raise ValueError("diagnostic_group_count_invalid")
        groups = []
        for item in value:
            if name == "group_affinity":
                _keys(item, ("group", "affinity_mask"))
                _integer(item["group"], 0, 0xFFFF)
                _integer(item["affinity_mask"], 0, 2**64 - 1)
                groups.append(item["group"])
            else:
                _integer(item, 0, 0xFFFF)
                groups.append(item)
        if len(set(groups)) != len(groups):
            raise ValueError("diagnostic_duplicate_group")
    else:
        raise ValueError("diagnostic_query_name_invalid")


def sanitize_diagnostics(value):
    """Reject unknown nested keys/types/stages and return a detached safe object.

    This validates an untrusted child's representation, not OS authenticity.
    The parent must additionally compare ``self`` to its own held-handle proof.
    """
    _keys(value, ("schema_version", "self", "self_rechecked", "ancestor_job_hierarchy", "effective_inherited_limits",
                  "control_eligibility", "process_control_writes", "immediate_job", "lineage", "errors"))
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("diagnostic_version_invalid")
    if (value["ancestor_job_hierarchy"] != "unknown" or value["effective_inherited_limits"] != "unknown"
            or value["control_eligibility"] != "not_assessed" or type(value["process_control_writes"]) is not int
            or value["process_control_writes"] != 0 or type(value["self_rechecked"]) is not bool):
        raise ValueError("diagnostic_scope_invalid")
    if value["self"] is not None:
        _validate_process(value["self"])
    _errors(value["errors"], 2)
    if value["self"] is None and (value["self_rechecked"] or not value["errors"]):
        raise ValueError("diagnostic_missing_self")
    if value["self_rechecked"] and value["errors"]:
        raise ValueError("diagnostic_self_state_invalid")
    job = value["immediate_job"]
    _keys(job, ("scope", "snapshot_atomic", "membership", "queries"))
    if job["scope"] != "current_process_immediate_job_only" or job["snapshot_atomic"] is not False:
        raise ValueError("diagnostic_job_scope_invalid")
    if job["membership"] not in ("present", "absent", "unknown"):
        raise ValueError("diagnostic_membership_invalid")
    if (job["membership"] != "unknown" and (value["self"] is None
            or (job["membership"] == "present") != value["self"]["in_any_job"])):
        raise ValueError("diagnostic_membership_mismatch")
    if job["membership"] == "unknown" and (value["self_rechecked"] or not value["errors"]):
        raise ValueError("diagnostic_unknown_membership_evidence_missing")
    _keys(job["queries"], QUERY_NAMES)
    for name, result in job["queries"].items():
        _keys(result, ("status", "value", "error"))
        if job["membership"] == "absent" and result["status"] != "not_applicable":
            raise ValueError("diagnostic_absent_job_query_invalid")
        if result["status"] == "valid":
            if result["error"] is not None or job["membership"] != "present":
                raise ValueError("diagnostic_query_state_invalid")
            _validate_value(name, result["value"])
        elif result["status"] == "unknown":
            if result["value"] is not None:
                raise ValueError("diagnostic_unknown_value_invalid")
            _validate_error(result["error"])
        elif result["status"] == "not_applicable":
            if result["value"] is not None or result["error"] is not None or job["membership"] != "absent":
                raise ValueError("diagnostic_query_state_invalid")
        else:
            raise ValueError("diagnostic_query_status_invalid")
    lineage = value["lineage"]
    _keys(lineage, ("semantics", "max_hops", "validity", "stop_reason", "parents", "errors"))
    if (lineage["semantics"] != "process_ancestry_not_job_hierarchy" or type(lineage["max_hops"]) is not int
            or lineage["max_hops"] != MAX_HOPS or lineage["validity"] not in ("verified_prefix", "unknown")
            or type(lineage["stop_reason"]) is not str or lineage["stop_reason"] not in STOP_REASONS):
        raise ValueError("diagnostic_lineage_scope_invalid")
    parents = lineage["parents"]
    if type(parents) is not list or len(parents) > MAX_HOPS:
        raise ValueError("diagnostic_lineage_count_invalid")
    if lineage["stop_reason"] == "hop_limit" and len(parents) != MAX_HOPS:
        raise ValueError("diagnostic_hop_limit_count_invalid")
    previous = value["self"]
    seen = set() if previous is None else {previous["pid"]}
    for index, parent in enumerate(parents):
        _keys(parent, ("process", "matches", "relation_rechecked", "creation_not_after_child"))
        _validate_process(parent["process"])
        _keys(parent["matches"], MATCH_FIELDS)
        if (any(type(item) is not bool for item in parent["matches"].values())
                or parent["relation_rechecked"] is not True or parent["creation_not_after_child"] is not True):
            raise ValueError("diagnostic_parent_verification_invalid")
        process = parent["process"]
        if previous is None or process["pid"] in seen or int(process["creation_filetime"]) >= int(previous["creation_filetime"]):
            raise ValueError("diagnostic_parent_order_invalid")
        if parent["matches"]["same_session"] != (process["session_id"] == value["self"]["session_id"]):
            raise ValueError("diagnostic_parent_session_mismatch")
        if not all(parent["matches"].values()) and (index != len(parents) - 1 or lineage["validity"] != "unknown"
                                                  or lineage["stop_reason"] != "security_boundary"):
            raise ValueError("diagnostic_security_boundary_invalid")
        seen.add(process["pid"])
        previous = process
    _errors(lineage["errors"], MAX_HOPS + 1)
    has_boundary = bool(parents and not all(parents[-1]["matches"].values()))
    if (lineage["stop_reason"] == "security_boundary") != has_boundary:
        raise ValueError("diagnostic_security_boundary_invalid")
    if has_boundary and not any(error["stage"] == "parent_security_boundary" for error in lineage["errors"]):
        raise ValueError("diagnostic_security_boundary_evidence_missing")
    if lineage["validity"] == "verified_prefix" and (not value["self_rechecked"] or lineage["errors"]
                                                      or lineage["stop_reason"] not in ("hop_limit", "parent_absent")):
        raise ValueError("diagnostic_lineage_state_invalid")
    return copy.deepcopy(value)
