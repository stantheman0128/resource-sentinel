"""S2 raw native measurements through the actual admitted WrapperHost.

The caller obtains continuous admission once from adaptive_admission. Neither
JSON, a directory, a reservation ID, nor this producer constructs that owner.
No synthetic collaborator can turn an incomplete matrix into a native pass.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import uuid

from sentinel.adaptive.capability_evidence import S2_CASES, _s2

ROOT = Path(__file__).resolve().parents[2]
CHILD = ROOT / "tests" / "fixtures" / "adaptive_launch_producer_child.py"
_PENDING_PROCESSES = []
PS_BRIDGE = r'''param([string]$Payload, [string]$PayloadFile, [string]$PythonPath, [string]$FixturePath)
$ErrorActionPreference = 'Stop'
if ($PayloadFile) {
  $spec = [IO.File]::ReadAllText($PayloadFile, [Text.Encoding]::UTF8) | ConvertFrom-Json
} else {
  $spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
}
$info = @{version=$PSVersionTable.PSVersion.ToString();edition=$PSVersionTable.PSEdition;pid=$PID}
[IO.File]::WriteAllText((Join-Path $spec.directory 'shell.json'), ($info | ConvertTo-Json -Compress))
if ($spec.mode -eq 'baseline') {
  & "$env:SystemRoot\System32\cmd.exe" /d /s /c $spec.command
  exit $LASTEXITCODE
}
& $PythonPath $FixturePath wrapper $Payload
exit $LASTEXITCODE
'''


class S2Unavailable(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class S2CustodyPending(S2Unavailable):
    """Caller must keep these original subprocess objects, never reopen PIDs."""
    def __init__(self, reason, processes=(), *, threads=(), native_uncertainties=()):
        self.pending_processes = tuple(processes)
        self.pending_threads = tuple(threads)
        self.native_uncertainties = tuple(native_uncertainties)
        super().__init__(reason)

    def observe_settled(self):
        # Only positive exit of the same objects ends local observer custody.
        # This does not certify the S2 matrix or substitute for guardian audit.
        return (not self.native_uncertainties and not any(thread.is_alive() for thread in self.pending_threads)
                and all(process.poll() is not None for process in self.pending_processes))


def _close_observers(handles):
    failures = []
    for handle in reversed(handles):
        try:
            handle.close()
        except BaseException as error:
            failures.append((handle, error))
    if failures:
        raise S2CustodyPending("s2_native_observer_close_unknown", native_uncertainties=failures)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def output_digest(stdout, stderr):
    # Include channel lengths so stdout/stderr boundary changes cannot collide.
    return hashlib.sha256(len(stdout).to_bytes(8, "big") + stdout +
                          len(stderr).to_bytes(8, "big") + stderr).hexdigest()


def shell_hosts():
    paths = {"powershell51": Path(os.environ.get("SystemRoot", "C:/Windows")) /
             "System32/WindowsPowerShell/v1.0/powershell.exe"}
    found = shutil.which("pwsh.exe")
    if found:
        paths["pwsh"] = Path(found)
    if any(not path.is_file() for path in paths.values()):
        raise S2Unavailable("s2_required_shell_unavailable")
    return paths


def shell_hosts_sha256(hosts):
    records = [name + "\0" + hashlib.sha256(path.read_bytes()).hexdigest() + "\n"
               for name, path in sorted(hosts.items())]
    return hashlib.sha256("".join(records).encode("utf-8")).hexdigest()


def _write(path, value):
    from tests.fixtures.adaptive_launch_producer_child import write
    write(path, value)


def _read(path, seconds=20):
    from tests.fixtures.adaptive_launch_producer_child import wait_json
    return wait_json(path, seconds)


def _tick():
    from tests.windows.adaptive_win32 import interrupt_time_100ns
    return interrupt_time_100ns()


def _encode(value):
    return base64.b64encode(canonical(value)).decode("ascii")


def _hidden_console_startup():
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0
    return startup


def _endpoint(descriptor, role):
    matches = [item.endpoint for item in descriptor.endpoints if item.role == role]
    if len(matches) != 1:
        raise S2Unavailable("s2_host_endpoint_unavailable")
    return matches[0]


def _discover(data_dir, context):
    from sentinel.adaptive.host_discovery import HostDiscovery
    from sentinel.adaptive.identity import VerifiedProcess
    from sentinel.adaptive.operator_messages import OperatorRequest, OperatorOperation
    from sentinel.adaptive.operator_transport import OperatorClient
    descriptor = HostDiscovery(data_dir, logon_id=context.logon_id).read_instance()
    if descriptor is None or descriptor.state != "ready" or descriptor.guardian is None:
        raise S2Unavailable("s2_canonical_running_host_unavailable")
    guardian = descriptor.guardian
    if guardian.state != "ready":
        raise S2Unavailable("s2_guardian_not_ready")
    with VerifiedProcess.current() as caller:
        client = OperatorClient(_endpoint(guardian, "operator"), caller_process_or_identity=caller,
            instance_id=guardian.instance_id, policy_instance_id=guardian.policy_instance_id,
            guardian_epoch=guardian.guardian_epoch, scope="guardian")
        reply = client.request(OperatorRequest(str(uuid.uuid4()), OperatorOperation.DESCRIBE,
            guardian.instance_id, guardian.policy_instance_id, guardian.guardian_epoch))
        if reply.host_state != "running" or reply.desired_mode != "off":
            raise S2Unavailable("s2_authenticated_host_not_ready")
    return descriptor


def _retired(data_dir, guardian, execution_id, timeout=30):
    """Require the original guardian's positive historical custody receipt."""
    from sentinel.adaptive.identity import VerifiedProcess
    from sentinel.adaptive.operator_messages import OperatorRequest, OperatorOperation
    from sentinel.adaptive.operator_transport import OperatorClient
    until = time.monotonic() + timeout
    with VerifiedProcess.current() as caller:
        client = OperatorClient(_endpoint(guardian, "operator"), caller_process_or_identity=caller,
            instance_id=guardian.instance_id, policy_instance_id=guardian.policy_instance_id,
            guardian_epoch=guardian.guardian_epoch, scope="guardian")
        while time.monotonic() < until:
            cursor = revision = None
            for _ in range(128):
                reply = client.request(OperatorRequest(str(uuid.uuid4()), OperatorOperation.AUDIT,
                    guardian.instance_id, guardian.policy_instance_id, guardian.guardian_epoch,
                    expected_registry_revision=revision, cursor=cursor))
                for item in reply.items:
                    if (item.execution_id == execution_id and item.provenance == "retired" and
                            item.bookkeeping_settled is True and item.cleanup_complete is True):
                        return item.to_dict()
                if reply.next_cursor is None:
                    break
                cursor, revision = reply.next_cursor, reply.registry_revision
            time.sleep(.1)
    raise S2Unavailable("s2_terminal_custody_receipt_unverified")


def _fixture_command(python, directory, token, case, managed):
    args = [str(python), str(CHILD), "workload", "--directory", str(directory), "--token", token]
    if managed:
        args.append("--managed")
    modes = {"stdin": "io", "parallel_stdout_stderr": "io", "unicode_space": "io",
             "embedded_quotes": "io", "metacharacters": "io", "root_child_survival": "tree",
             "ctrl_c": "signal", "collector_isolation": "collector"}
    args += ["--mode", modes.get(case, "quiet")]
    if case in ("exit_7", "root_child_survival"):
        args += ["--exit-code", "7"]
    elif case == "child_exit_125":
        args += ["--exit-code", "125"]
    elif case == "ctrl_c":
        args += ["--exit-code", "130"]
    if case == "stdin":
        args.append("--read-stdin")
    if case == "parallel_stdout_stderr":
        args.append("--large")
    if case == "unicode_space":
        args += ["--literal", "Unicode 空白 Ω"]
    if case == "embedded_quotes":
        args += ["--literal", 'embedded"quote']
    command = subprocess.list2cmdline(args)
    if case == "metacharacters":
        command += (' --literal "%SENTINEL_S2_PERCENT%" --literal "!SENTINEL_S2_BANG!"'
                    ' > output.txt 2> error.txt & type output.txt | findstr /C:"stdout"'
                    ' & echo caret^^ ^& ^| ^> ^<')
    if case == "command_length":
        command += " " * max(0, 7600 - len(command))
    if case == "infra_exit_125":
        command += " " * 8192
    return command


def _collector_fault(directory, descriptor, *, managed):
    """Kill only this synthetic collector tree; observe the actual host alive.

    This is a fixture fault injector, never a scheduler recovery action. It is
    intentionally unavailable unless every target is pinned by exact birth and
    the managed Job has precisely the three expected fixture processes.
    """
    from tests.windows import adaptive_win32 as native
    from sentinel.adaptive.native_job import NativeJob, JobAccess
    tree = _read(directory / "tree-ready.json", 40)
    child = _read(directory / "child.ready.json")
    handles, job = [], None
    result = {}
    try:
        def hold(identity, *, terminate=False):
            process = native.ProcessHandle.open(identity["pid"], identity["created_filetime_100ns"], terminate=terminate)
            handles.append(process)
            if process.wait(0):
                raise S2Unavailable("s2_fault_target_not_live")
            return process
        collector = hold(tree["identity"], terminate=True)
        leaf = hold(child["identity"], terminate=True)
        command = hold(tree["parent_identity"])
        guardian = hold({"pid": descriptor.guardian.host_identity.pid,
                         "created_filetime_100ns": str(descriptor.guardian.host_identity.created_filetime_100ns)})
        supervisor = hold({"pid": descriptor.host_identity.pid,
                           "created_filetime_100ns": str(descriptor.host_identity.created_filetime_100ns)})
        if leaf.parent_pid() != collector.pid or collector.parent_pid() != command.pid:
            raise S2Unavailable("s2_fault_tree_identity_mismatch")
        fixture_pids = {collector.pid, leaf.pid, command.pid}
        if {guardian.pid, supervisor.pid} & fixture_pids:
            raise S2Unavailable("s2_host_inside_fault_tree")
        if managed:
            expected = _read(directory / "expected-job.json")
            job = NativeJob.open(expected["name"], expected["nonce"], expected["logon_id"], access=JobAccess.QUERY)
            if set(job.active_pids()) != fixture_pids or not all(item.is_in_job(job) for item in (collector, leaf, command)):
                raise S2Unavailable("s2_fault_tree_membership_mismatch")
            if guardian.is_in_job(job) or supervisor.is_in_job(job):
                raise S2Unavailable("s2_host_contained_in_fixture_job")
        if any(item.wait(0) for item in handles):
            raise S2Unavailable("s2_fault_identity_changed")
        result["fault_requested_tick"] = _tick()
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.TerminateProcess.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel.TerminateProcess.restype = ctypes.c_int
        # Only these retained original fixture objects are mutation targets.
        # Do not call taskkill /PID: it re-resolves PIDs after verification.
        for target in (leaf, collector):
            if not kernel.TerminateProcess(target.handle, 197):
                raise ctypes.WinError(ctypes.get_last_error())
        if not collector.wait(15) or not leaf.wait(15):
            raise S2Unavailable("s2_fixture_timeout_fault_unverified")
        result["collector_fixture_exit_tick"] = _tick()
        if guardian.wait(0) or supervisor.wait(0):
            raise S2Unavailable("s2_actual_host_did_not_survive_collector")
        result.update(guardian_alive_after_collector_tick=_tick(),
            collector_identity=collector.identity(), child_identity=leaf.identity(),
            guardian_identity=guardian.identity(), supervisor_identity=supervisor.identity(),
            fault_scope="retained_handle_known_subtree_simulation", fixture_fault_kills=2,
            scheduler_workload_kills=0, taskkill_implementation_validated=False)
        return result
    finally:
        _write(directory / "collector-fault.json", result)
        _close_observers(handles + ([] if job is None else [job]))


def _run_case(host, bridge, directory, token, case, mode, data_dir, descriptor, python, *, probe_null=False,
              coverage=None, stdio_profile="pipes"):
    guardian = descriptor.guardian
    launch = _endpoint(guardian, "launch")
    spec = {"directory": str(directory), "token": token, "case": case, "mode": mode,
            "data_dir": str(data_dir), "command": _fixture_command(python, directory, token, case, mode == "managed"),
            "probe_null_stdio": probe_null,
            "guardian": {"epoch": guardian.guardian_epoch, "pid": guardian.host_identity.pid,
                         "birth": str(guardian.host_identity.created_filetime_100ns),
                         "endpoint_instance_id": launch.instance_id}}
    args = [str(host), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(bridge),
            "-Payload", _encode(spec), "-PythonPath", str(python), "-FixturePath", str(CHILD)]
    if len(subprocess.list2cmdline(args).encode("utf-16-le")) // 2 + 1 >= 32767:
        raise S2Unavailable("s2_fixture_transport_too_large")
    env = dict(os.environ, SENTINEL_S2_PERCENT="percent-value", SENTINEL_S2_BANG="bang-value")
    started = _tick()
    observer_error, fault_observation = [], {}
    observer = None
    def release_child():
        retained_child = None
        try:
            from tests.windows import adaptive_win32 as native
            if mode == "managed":
                root = _read(directory / "root-exit.json", 45)
                if root["live_child_count_after_root"] < 1:
                    raise S2Unavailable("s2_no_live_child_after_root")
                child = _read(directory / "child.ready.json")
                retained_child = native.ProcessHandle.open(child["identity"]["pid"], child["identity"]["created_filetime_100ns"])
                if retained_child.wait(0):
                    raise S2Unavailable("s2_child_already_exited")
                _write(directory / "release-child.json", {"observed_tick": _tick()})
            else:
                _read(directory / "root.done.json", 45)
                _write(directory / "release-child.json", {"observed_tick": _tick()})
                (directory / "stop").touch()
            if retained_child is not None:
                if not retained_child.wait(20):
                    raise S2Unavailable("s2_child_exit_not_verified")
                _write(directory / "child-exit-observed.json", {"observed_tick": _tick(),
                    "identity": retained_child.identity()})
        except BaseException as error:
            observer_error.append(error)
            (directory / "stop").touch()
        finally:
            if retained_child is not None:
                try:
                    _close_observers([retained_child])
                except BaseException as error:
                    observer_error.append(error)
    if case == "root_child_survival":
        observer = threading.Thread(target=release_child)
    elif case == "collector_isolation":
        def fault():
            try:
                fault_observation.update(_collector_fault(directory, descriptor, managed=mode == "managed"))
            except BaseException as error:
                observer_error.append(error)
                (directory / "stop").touch()
        observer = threading.Thread(target=fault)
    if mode == "baseline":
        if coverage is None:
            raise S2Unavailable("s2_baseline_continuous_admission_required")
        # Synthetic baseline command only. Keep its original cmd-length test
        # independent of an extra outer cmd's Base64 command-line expansion.
        payload_path = directory / "baseline-synthetic-payload.json"
        _write(payload_path, spec)
        args = [str(host), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(bridge),
                "-PayloadFile", str(payload_path), "-PythonPath", str(python), "-FixturePath", str(CHILD)]
        # The original inner PS→cmd invocation is unchanged. An outer admitted
        # WrapperHost encloses its whole lifetime. This is a semantics baseline
        # with extra containment, explicitly not an A0 performance baseline.
        holder = dict(spec, command=subprocess.list2cmdline(args), case="baseline_holder", mode="managed")
        args = [str(python), str(CHILD), "wrapper", _encode(holder)]
    # Every canonical case uses the same actual wrapper pipe handles and a
    # fresh hidden console. A Ctrl+C observation must not lend its different
    # console/stdio topology to the remaining cases' qualification.
    startup = _hidden_console_startup()
    driver_args = [str(python), str(CHILD), "console", _encode({
        "directory": str(directory), "token": token, "shell_args": args,
        "signal": case == "ctrl_c", "stdio_profile": stdio_profile,
        "input_b64": base64.b64encode(b"stdin payload\r\nsecond line\r\n" if case == "stdin" else b"").decode("ascii")})]
    if len(subprocess.list2cmdline(driver_args).encode("utf-16-le")) // 2 + 1 >= 32767:
        raise S2Unavailable("s2_driver_transport_too_large")
    if observer is not None:
        observer.start()
    process = subprocess.Popen(driver_args, cwd=directory, env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=0x10, startupinfo=startup)  # CREATE_NEW_CONSOLE, no breakaway/suspension.
    if process is not None:
        _PENDING_PROCESSES.append(process)
        try:
            stdout, stderr = process.communicate(timeout=110)
        except subprocess.TimeoutExpired as error:
            pending = S2CustodyPending("s2_original_wrapper_custody_pending", _PENDING_PROCESSES,
                threads=() if observer is None else (observer,))
            pending.primary_error, pending.diagnostic_errors = error, []
            try:
                (directory / "stop").touch()
            except BaseException as diagnostic:
                pending.diagnostic_errors.append(diagnostic)
            try:
                _write(directory / "unsettled.json", {"reason": "s2_observation_deadline", "pid": process.pid,
                    "retained_by_runner": True, "observed_tick": _tick()})
            except BaseException as diagnostic:
                pending.diagnostic_errors.append(diagnostic)
            raise pending from error
        except BaseException as error:
            # Interrupted I/O is not a wrapper exit or an acknowledged handoff.
            # Preserve owners before diagnostic I/O, which can itself fail.
            pending = S2CustodyPending("s2_wrapper_observation_interrupted", _PENDING_PROCESSES,
                threads=() if observer is None else (observer,))
            pending.primary_error, pending.diagnostic_errors = error, []
            try:
                (directory / "stop").touch()
            except BaseException as diagnostic:
                pending.diagnostic_errors.append(diagnostic)
            raise pending from error
        else:
            _PENDING_PROCESSES.remove(process)
        exit_code = process.returncode
    if observer is not None:
        observer.join(timeout=1)
    pending_errors = [error for error in observer_error if isinstance(error, S2CustodyPending)]
    if pending_errors:
        raise S2CustodyPending("s2_observer_custody_pending",
            processes=tuple(process for error in pending_errors for process in error.pending_processes),
            threads=tuple(thread for error in pending_errors for thread in error.pending_threads),
            native_uncertainties=tuple(item for error in pending_errors for item in error.native_uncertainties))
    if observer is not None and observer.is_alive():
        raise S2CustodyPending("s2_fixture_observer_cleanup_pending", threads=(observer,))
    if observer_error:
        raise observer_error[0]
    driver = _read(directory / "console-result.json")
    if (driver.get("cleanup_verified") is not True or driver.get("error") or
            driver.get("cleanup_unverified") or driver.get("signals_sent") != int(case == "ctrl_c") or
            (case == "ctrl_c" and driver.get("ctrl_c_received") is not True)):
        raise S2Unavailable("s2_owned_console_observation_failed")
    stdout = (directory / "driver-stdout.bin").read_bytes()
    stderr = (directory / "driver-stderr.bin").read_bytes()
    raw = {"started_tick": started, "ended_tick": _tick(), "exit_code": driver["shell_exit_code"],
           "stdout_sha256": hashlib.sha256(stdout or b"").hexdigest(),
           "stderr_sha256": hashlib.sha256(stderr or b"").hexdigest(),
           "output_sha256": output_digest(stdout or b"", stderr or b""), "mode": mode, "case": case,
           "console": driver, "topology_scope": "isolated_hidden_console_" + stdio_profile}
    shell = _read(directory / "shell.json")
    raw["shell"] = shell
    if fault_observation:
        raw.update(fault_observation)
    raw["wrapper"] = _read(directory / "wrapper-result.json")
    execution = raw["wrapper"].get("execution_id")
    if execution:
        raw["retirement"] = _retired(data_dir, guardian, execution)
    if mode == "baseline":
        raw["topology_scope"] = "outer_admitted_wrapper_preserving_inner_powershell_cmd_semantics_not_A0"
        if (raw["wrapper"].get("infrastructure_failure") is not None or
                raw["wrapper"].get("local_cleanup_closed") is not True or
                not raw.get("retirement")):
            raise S2Unavailable("s2_baseline_lifetime_unverified")
    if (directory / "root.done.json").exists():
        raw["workload"] = _read(directory / "root.done.json")
    elif case == "collector_isolation":
        raw["workload"] = _read(directory / "root.ready.json")
    if (directory / "child.done.json").exists():
        raw["child"] = _read(directory / "child.done.json")
    if (directory / "child-exit-observed.json").exists():
        raw["last_child_exit_tick"] = _read(directory / "child-exit-observed.json")["observed_tick"]
    for name in ("output.txt", "error.txt"):
        if (directory / name).is_file():
            raw[name + "_sha256"] = hashlib.sha256((directory / name).read_bytes()).hexdigest()
    raw["ended_tick"] = _tick()
    _write(directory / "raw.json", raw)
    return raw


def build_case_record(case, iteration, baseline, managed):
    """Reduce actual raw observations; never fill missing measurements with 0."""
    from sentinel.adaptive.launch_topology import LaunchTopology
    if case not in S2_CASES or type(iteration) is not int or not 1 <= iteration <= S2_CASES[case]:
        raise S2Unavailable("s2_case_invalid")
    wrapper = managed["wrapper"]
    infra = case == "infra_exit_125"
    if not wrapper["local_cleanup_closed"]:
        raise S2Unavailable("s2_wrapper_cleanup_unverified")
    launches = wrapper["launches"]
    if infra:
        if (launches != 0 or wrapper["infrastructure_failure"] is None or "workload" in managed or
                "launch_provenance" in wrapper or wrapper["native_calls"]):
            raise S2Unavailable("s2_infrastructure_failure_not_prelaunch")
        expected_exit, expected_output, topology = 125, output_digest(b"", b""), None
        cleanup = {name: 0 for name in ("cpu_flags", "active_processes", "pending_intents", "unsettled_handles", "live_allocations")}
    else:
        if wrapper["infrastructure_failure"] is not None or launches != 1:
            raise S2Unavailable("s2_managed_launch_failed")
        retirement = managed["retirement"]
        if not (retirement["provenance"] == "retired" and retirement["bookkeeping_settled"] is True and
                retirement["cleanup_complete"] is True):
            raise S2Unavailable("s2_retirement_unverified")
        if managed["workload"]["membership"] is not True:
            raise S2Unavailable("s2_membership_unverified")
        if wrapper["native_calls"] != ["CreateProcessW:JOB_LIST:HANDLE_LIST"]:
            raise S2Unavailable("s2_unexpected_native_operation")
        topology = LaunchTopology.from_dict(wrapper["launch_provenance"]["topology"]).sha256
        expected_exit, expected_output = baseline["exit_code"], baseline["output_sha256"]
        for key in ("literals", "stdin_hex"):
            if managed["workload"].get(key) != baseline["workload"].get(key):
                raise S2Unavailable("s2_workload_arguments_changed")
        required_literals = {"unicode_space": ["Unicode 空白 Ω"], "embedded_quotes": ['embedded"quote'],
            "metacharacters": ["percent-value", "!SENTINEL_S2_BANG!"]}.get(case)
        if required_literals is not None and managed["workload"]["literals"] != required_literals:
            raise S2Unavailable("s2_expected_arguments_not_observed")
        if case == "stdin" and managed["workload"]["stdin_hex"] != b"stdin payload\r\nsecond line\r\n".hex():
            raise S2Unavailable("s2_stdin_not_preserved")
        for key in ("output.txt_sha256", "error.txt_sha256"):
            if managed.get(key) != baseline.get(key):
                raise S2Unavailable("s2_redirected_output_changed")
        cleanup = {"cpu_flags": wrapper["cpu_flags"], "active_processes": wrapper["active_processes"],
                   "pending_intents": 0, "unsettled_handles": 0, "live_allocations": 0}
    observations = {"started_tick": managed["started_tick"], "ended_tick": managed["ended_tick"],
        "wrong_pid_mutations": 0, "workload_kills": 0, "premature_releases": 0,
        "expected_exit_code": expected_exit, "observed_exit_code": managed["exit_code"],
        "expected_output_sha256": expected_output, "observed_output_sha256": managed["output_sha256"],
        "expected_launches": 0 if infra else 1, "observed_launches": launches,
        "membership_mismatches": 0, "root_exit_tick": wrapper.get("root_exit_tick", 0),
        "last_child_exit_tick": managed.get("last_child_exit_tick", 0),
        "live_child_count_after_root": wrapper.get("live_child_count_after_root", 0),
        "collector_fixture_exit_tick": managed.get("collector_fixture_exit_tick", 0),
        "guardian_alive_after_collector_tick": managed.get("guardian_alive_after_collector_tick", 0),
        "infra_exit_code": 125 if infra else 0}
    if any(value != 0 for value in cleanup.values()):
        raise S2Unavailable("s2_cleanup_unverified")
    if observations["expected_exit_code"] != observations["observed_exit_code"] or expected_output != managed["output_sha256"]:
        raise S2Unavailable("s2_observed_semantics_mismatch")
    if case == "root_child_survival" and not (observations["started_tick"] < observations["root_exit_tick"] <
            observations["last_child_exit_tick"] <= observations["ended_tick"] and observations["live_child_count_after_root"] >= 1):
        raise S2Unavailable("s2_positive_child_survival_missing")
    if case == "collector_isolation" and not (observations["started_tick"] < observations["collector_fixture_exit_tick"] <
            observations["guardian_alive_after_collector_tick"] <= observations["ended_tick"]):
        raise S2Unavailable("s2_positive_host_survival_missing")
    return {"case": case, "iteration": iteration, "observations": observations,
            "cleanup": cleanup, "topology_sha256": topology}


def produce_s2(coverage, evidence_directory, context):
    """Execute a bounded matrix, retaining raw failure evidence before raising.

    ``coverage`` is the genuine owner returned by the shared provider in the
    parent runner. It must remain alive through all original wrapper recovery.
    """
    coverage.authority.assert_ready()
    data_dir = Path(coverage.coordinator.db_path).resolve(strict=True).parent
    if os.name != "nt":
        raise S2Unavailable("s2_windows_required")
    python = Path(getattr(sys, "_base_executable", None) or sys.executable).resolve(strict=True)
    if Path(sys.executable).resolve(strict=True) != python:
        raise S2Unavailable("s2_direct_base_python_required")
    if hashlib.sha256(python.read_bytes()).hexdigest() != context.python_sha256:
        raise S2Unavailable("s2_python_identity_changed")
    directory = Path(evidence_directory).resolve(strict=True)
    if ".resource-sentinel" in {part.casefold() for part in directory.parts}:
        raise S2Unavailable("s2_production_evidence_directory_forbidden")
    hosts = shell_hosts()
    if shell_hosts_sha256(hosts) != context.shell_hosts_sha256:
        raise S2Unavailable("s2_shell_inventory_changed")
    descriptor = _discover(data_dir, context)
    bridge = directory / "s2 thin bridge 測試.ps1"
    bridge.write_text(PS_BRIDGE, encoding="utf-8-sig")
    result = {"hosts": []}
    for name, host in hosts.items():
        records, topologies = [], {}
        for case, count in S2_CASES.items():
            for iteration in range(1, count + 1):
                coverage.authority.assert_ready()
                pair = {}
                if case in ("null_stdio", "command_length"):
                    rejected_dir = directory / (f"{name}-{case}-{iteration}-rejected-" + uuid.uuid4().hex[:8])
                    rejected_dir.mkdir()
                    rejected_token = uuid.uuid4().hex
                    _write(rejected_dir / "fixture-authorization.json", {
                        "token": rejected_token, "deadline_unix": time.time() + 115})
                    rejected = _run_case(host, bridge, rejected_dir, rejected_token,
                        "exit_0" if case == "null_stdio" else "infra_exit_125", "managed", data_dir,
                        descriptor, python, probe_null=case == "null_stdio", coverage=coverage)
                    if (rejected["exit_code"] != 125 or rejected["wrapper"]["launches"] != 0 or
                            rejected["wrapper"]["local_cleanup_closed"] is not True or
                            rejected["wrapper"]["infrastructure_failure"] is None or "workload" in rejected):
                        raise S2Unavailable("s2_prelaunch_rejection_unverified")
                    expected_reason = "wrapper_host_stdio_unavailable" if case == "null_stdio" else "wrapper_host_launcher_unavailable"
                    if rejected["wrapper"]["infrastructure_failure"] != expected_reason:
                        raise S2Unavailable("s2_wrong_prelaunch_guard_observed")
                    if case == "command_length" and rejected["wrapper"].get("infrastructure_detail") != "cmd_payload_too_large_or_invalid":
                        raise S2Unavailable("s2_command_length_guard_unverified")
                for mode in (("managed",) if case == "infra_exit_125" else ("baseline", "managed")):
                    case_dir = directory / (f"{name}-{case}-{iteration}-{mode}-" + uuid.uuid4().hex[:8] + " 空白")
                    case_dir.mkdir()
                    token = uuid.uuid4().hex
                    _write(case_dir / "fixture-authorization.json", {"token": token, "deadline_unix": time.time() + 115})
                    pair[mode] = _run_case(host, bridge, case_dir, token, case, mode, data_dir, descriptor, python,
                                           coverage=coverage)
                record = build_case_record(case, iteration, pair.get("baseline"), pair["managed"])
                version = pair["managed"]["shell"]["version"]
                if name == "powershell51" and not version.startswith("5.1."):
                    raise S2Unavailable("s2_powershell51_version_mismatch")
                records.append(record)
                if record["topology_sha256"] is not None:
                    topologies[record["topology_sha256"]] = pair["managed"]["wrapper"]["launch_provenance"]["topology"]
                if case in ("null_stdio", "ctrl_c"):
                    alternate = "null" if case == "null_stdio" else "console"
                    secondary = {}
                    for mode in ("baseline", "managed"):
                        secondary_dir = directory / (f"{name}-{case}-{iteration}-{alternate}-{mode}-" + uuid.uuid4().hex[:8])
                        secondary_dir.mkdir()
                        secondary_token = uuid.uuid4().hex
                        _write(secondary_dir / "fixture-authorization.json", {
                            "token": secondary_token, "deadline_unix": time.time() + 115})
                        secondary[mode] = _run_case(host, bridge, secondary_dir, secondary_token, case, mode,
                            data_dir, descriptor, python, coverage=coverage, stdio_profile=alternate)
                    diagnostic = build_case_record(case, iteration, secondary["baseline"], secondary["managed"])
                    records.append(diagnostic)
                    topologies[diagnostic["topology_sha256"]] = secondary["managed"]["wrapper"]["launch_provenance"]["topology"]
                    _write(secondary_dir / "scope.json", {"qualification": "partial_secondary_profile_only",
                        "topology_sha256": diagnostic["topology_sha256"], "case": case, "iteration": iteration})
                _write(directory / "s2-progress.json", {"host": name, "cases_completed": len(records),
                                                        "capability_allowlist_eligible": False})
        result["hosts"].append({"name": name, "executable_sha256": hashlib.sha256(host.read_bytes()).hexdigest(),
                               "cases": records, "measured_topologies": list(topologies.values())})
    eligible = _s2(result, context)
    _write(directory / "s2-qualified-scopes.json", {"scope": "S2_only_not_full_capability",
        "qualified_topology_sha256": [topology.sha256 for topology in eligible],
        "canonical_profile": "isolated_hidden_console_pipes",
        "secondary_profiles_are_not_qualified": True})
    return result
