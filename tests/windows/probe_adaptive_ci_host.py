"""Public, read-only Windows host observation; never authorizes native control.

No Sentinel imports, DB access, process launch, Job creation, or control APIs.
Only allowlisted machine facts are printed; no process identity or environment
dump is collected. A successful observation may describe an unsupported host.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
import platform
import re
import sys


ERROR_STAGES = frozenset({
    "native_platform", "native_api", "IsProcessInJob", "ProcessIdToSessionId",
    "GetActiveProcessorGroupCount", "GetActiveProcessorCount",
    "GetProcessAffinityMask", "QueryInformationJobObject",
})


def _integer(value, minimum=0, maximum=2**64 - 1):
    return value if type(value) is int and minimum <= value <= maximum else None


def _boolean(value):
    return value if type(value) is bool else None


def _version(value):
    # Image metadata is intentionally a tiny allowlist, never arbitrary env text.
    return value if isinstance(value, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value) and len(value) <= 32 else None


def public_report(observation, image_os=None, image_version=None):
    """Keep unknown distinct from false and omit arbitrary strings/identities."""
    errors = []
    for item in observation.get("errors", []):
        stage = item.get("stage")
        errors.append({"stage": stage if stage in ERROR_STAGES else "native_api",
                       "win32_error": _integer(item.get("win32_error"), maximum=2**32 - 1)})
    in_job = _boolean(observation.get("in_any_job"))
    groups = _integer(observation.get("processor_groups"), 1, 65535)
    processors = _integer(observation.get("logical_processors"), 1, 65535)
    process_mask = _integer(observation.get("process_affinity"), 1)
    system_mask = _integer(observation.get("system_affinity"), 1)
    bits = _integer(observation.get("python_bits"), 32, 64)
    session_zero = _boolean(observation.get("session_zero"))
    reasons = []
    if errors or None in (in_job, groups, processors, process_mask, system_mask, bits, session_zero):
        reasons.append("observation_unknown")
    if in_job is True:
        reasons.append("foreign_or_unknown_parent_job")
    if groups is not None and groups != 1:
        reasons.append("multiple_processor_groups")
    if processors is not None and processors > 64:
        reasons.append("processor_count_unsupported")
    if process_mask is not None and system_mask is not None and (
        process_mask != system_mask or system_mask.bit_count() != processors
    ):
        reasons.append("restricted_or_unknown_affinity")
    if bits is not None and bits != 64:
        reasons.append("python_bitness_unsupported")
    return {
        "schema_version": 1,
        "observation": "read_only_host_topology",
        "os_build": _integer(observation.get("os_build")),
        "python_version": _version(observation.get("python_version")),
        "python_bits": bits,
        "runner_image_os": image_os if image_os in {"win22", "win25"} else None,
        "runner_image_version": _version(image_version),
        "in_any_job": in_job,
        "session_zero": session_zero,
        "processor_groups": groups,
        "logical_processors": processors,
        "process_affinity": process_mask,
        "system_affinity": system_mask,
        "immediate_job_cpu_flags": _integer(observation.get("immediate_job_cpu_flags"), maximum=2**32 - 1),
        "validity": "unknown" if "observation_unknown" in reasons else "valid",
        "topology_candidate": not reasons,
        "topology_blockers": reasons,
        "errors": errors,
        # These require separate experiments and retained lifecycle authority.
        "interactive_context_verified": False,
        "continuous_admission_verified": False,
        "p1_capability_verified": False,
        "control_performed": False,
    }


def observe():
    result = {"errors": [], "python_bits": c.sizeof(c.c_void_p) * 8,
              "python_version": platform.python_version()}
    if sys.platform != "win32":
        result["errors"].append({"stage": "native_platform", "win32_error": None})
        return result
    result["os_build"] = sys.getwindowsversion().build
    kernel = c.WinDLL("kernel32", use_last_error=True)

    def bind(name, returns, *arguments):
        function = getattr(kernel, name)
        function.restype, function.argtypes = returns, list(arguments)
        return function

    current = bind("GetCurrentProcess", w.HANDLE)()
    is_in_job = bind("IsProcessInJob", w.BOOL, w.HANDLE, w.HANDLE, c.POINTER(w.BOOL))
    session_id = bind("ProcessIdToSessionId", w.BOOL, w.DWORD, c.POINTER(w.DWORD))
    group_count = bind("GetActiveProcessorGroupCount", w.WORD)
    processor_count = bind("GetActiveProcessorCount", w.DWORD, w.WORD)
    affinity = bind("GetProcessAffinityMask", w.BOOL, w.HANDLE,
                    c.POINTER(c.c_size_t), c.POINTER(c.c_size_t))
    query_job = bind("QueryInformationJobObject", w.BOOL, w.HANDLE, c.c_int,
                     c.c_void_p, w.DWORD, c.POINTER(w.DWORD))

    def failed(stage):
        result["errors"].append({"stage": stage, "win32_error": c.get_last_error()})

    in_job, session = w.BOOL(), w.DWORD()
    if is_in_job(current, None, c.byref(in_job)):
        result["in_any_job"] = bool(in_job.value)
    else:
        failed("IsProcessInJob")
    if session_id(os.getpid(), c.byref(session)):
        result["session_zero"] = session.value == 0
    else:
        failed("ProcessIdToSessionId")
    groups = group_count()
    if groups:
        result["processor_groups"] = groups
    else:
        # This API documents zero on failure but no GetLastError contract.
        result["errors"].append({"stage": "GetActiveProcessorGroupCount", "win32_error": None})
    processors = processor_count(0xFFFF)  # ALL_PROCESSOR_GROUPS
    if processors:
        result["logical_processors"] = processors
    else:
        failed("GetActiveProcessorCount")
    process_mask, system_mask = c.c_size_t(), c.c_size_t()
    if affinity(current, c.byref(process_mask), c.byref(system_mask)):
        result.update(process_affinity=process_mask.value, system_affinity=system_mask.value)
    else:
        failed("GetProcessAffinityMask")
    if result.get("in_any_job") is True:
        # NULL queries only the immediate inherited Job, not the entire chain.
        # Zero CPU flags therefore never establish a known CPU denominator.
        class CpuRate(c.Structure):
            _fields_ = [("flags", w.DWORD), ("union_value", w.DWORD)]

        cpu = CpuRate()
        if query_job(None, 15, c.byref(cpu), c.sizeof(cpu), None):
            result["immediate_job_cpu_flags"] = cpu.flags
        else:
            failed("QueryInformationJobObject")
    return result


def main():
    try:
        observation = observe()
    except Exception:
        # A traceback or exception string could expose a local path or context.
        observation = {"errors": [{"stage": "native_api", "win32_error": None}]}
    report = public_report(observation, os.environ.get("ImageOS"), os.environ.get("ImageVersion"))
    print(json.dumps(report, sort_keys=True))
    return 0 if report["validity"] == "valid" else 2


if __name__ == "__main__":
    raise SystemExit(main())
