"""P1 S2: explicit, isolated Windows launch capability evidence.

Run only through normal Sentinel admission, with both
SENTINEL_ADAPTIVE_WINDOWS_SPIKES=1 and SENTINEL_ADAPTIVE_SPIKE_DIR pointing to
an isolated evidence directory. No production wrapper or runtime configuration
is loaded or changed. Skips mean NOT VERIFIED, not a supported host. This file also supplies
the test-only Base64 launch host used by a generated thin PowerShell fixture.
The continuous-admission provider is unavailable; native setup and direct
fixture launch/console entry points fail closed before any native operation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tests.windows.adaptive_admission import (  # noqa: E402
    ContinuousAdmissionUnavailable, require_continuous_admission,
)
from sentinel.adaptive import launch_spec as launch_transport  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "adaptive_spawn_tree.py"
CMD_LIMIT = 8191
CREATE_PROCESS_LIMIT = 32767


def utf16_units(value: str) -> int:
    return launch_transport.utf16_units(value)


def encoded_spec(spec: dict) -> str:
    return base64.b64encode(json.dumps(spec, ensure_ascii=False).encode("utf-8")).decode("ascii")


def validate_launch_lengths(command: str, encoded: str, cmd_path: str, python: str, host: str) -> None:
    # cmd and CreateProcess have different limits. Successful Base64 transport
    # does not establish that cmd can execute the payload or its expansions.
    launch_transport.build_cmd_command_line(command, cmd_path=cmd_path)
    # The S2 envelope has fixture-only authorization fields. The common host
    # transport validates its Base64/argv/length, not those fields or readiness.
    launch_transport.prepare_encoded_host_command(encoded,
        python_executable=python, host_path=host)


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def wait_file(path: Path, seconds: float = 10) -> dict:
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if path.is_file():
            return json.loads(path.read_text("utf-8"))
        time.sleep(0.02)
    raise AssertionError("fixture_evidence_timeout: " + path.name)


def run_without_timeout_kill(args: list[str], *, timeout: float, input: bytes | None = None,
                             cwd=None, env=None, stdin=None) -> subprocess.CompletedProcess:
    """Unlike subprocess.run(timeout=...), never kill a process on timeout."""
    process = subprocess.Popen(args, stdin=subprocess.PIPE if input is not None else stdin,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, env=env)
    output, errors = process.communicate(input=input, timeout=timeout)
    return subprocess.CompletedProcess(args, process.returncode, output, errors)


def _native():
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tests.windows import adaptive_win32
    return adaptive_win32


def _launch_host(payload: str) -> int:
    if os.environ.get("SENTINEL_ADAPTIVE_WINDOWS_SPIKES") != "1":
        return 125
    try:
        require_continuous_admission()
    except ContinuousAdmissionUnavailable:
        return 125
    spec = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    directory = Path(spec["directory"]).resolve(strict=True)
    if ".resource-sentinel" in (part.casefold() for part in directory.parts):
        return 125
    authority = json.loads((directory / "fixture-authorization.json").read_text("utf-8"))
    remaining = float(authority["deadline_unix"]) - time.time()
    if authority["token"] != spec["token"] or not 0 < remaining <= 120:
        return 125
    timer = threading.Timer(remaining, lambda: os._exit(125))
    timer.daemon = True
    timer.start()
    cmd = str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe")
    outcome = {"schema_version": 1, "root_launched": False, "infrastructure_failure": None}
    if spec.get("console_fixture"):
        # Only this opt-in console test host installs a cancellation recorder.
        # Signal delivery still comes from the common fixture console; it never
        # kills the child or treats the request as Job completion.
        signal.signal(signal.SIGINT, lambda *_: outcome.update(cancel_signal_requested=True))
    job = process = None
    try:
        validate_launch_lengths(spec["command"], payload, cmd, sys.executable, str(Path(__file__).resolve()))
        native = _native()
        outcome["host_capability"] = native.require_supported_host()
        job = native.OwnedJob.create()
        write_json(directory / "expected-job.json", {"name": job.name, "nonce": job.nonce})
        if spec.get("observer_handshake"):
            until = time.monotonic() + 10
            while not (directory / "observer-ready").exists() and time.monotonic() < until:
                time.sleep(0.02)
            if not (directory / "observer-ready").exists():
                raise RuntimeError("observer_handshake_timeout")
        # The raw synthetic command is passed intact to the established cmd
        # semantics; no split/rejoin, no post-spawn assignment, no retry.
        command_line = launch_transport.build_cmd_command_line(spec["command"], cmd_path=cmd)
        try:
            process = native.launch_in_job(job, cmd, command_line, cwd=str(directory))
        except native.LaunchOutcomeUnknown as exc:
            process = exc.process
            outcome.update(root_launched=True, launch_outcome_unknown=True)
            # Keep the exact handle, never retry, and observe the fixture's own
            # bounded completion. Closing a Job is not reconciliation evidence.
            outcome["root_observed_exited"] = process.wait(min(110, remaining))
            raise
        outcome["root_launched"] = True
        outcome.update(root_identity=process.identity(),
                       root_in_job=process.is_in_job(job), wrapper_identity=native.current_identity())
        write_json(directory / "launch.json", outcome)
        if not outcome["root_in_job"]:
            raise RuntimeError("root_membership_mismatch")
        if not process.wait(min(110, remaining)):
            raise RuntimeError("fixture_root_deadline")
        outcome.update(root_exit_code=process.exit_code(), job_after_root=job.accounting(),
                       cpu_control=job.query_cpu())
        write_json(directory / "root-exit.json", outcome)
        return int(outcome["root_exit_code"])
    except Exception as exc:
        known_preflight = {"cmd_payload_too_large_or_invalid", "launch_payload_too_large"}
        outcome["infrastructure_failure"] = (str(exc) if isinstance(exc, ValueError) and str(exc) in known_preflight
                                             else getattr(exc, "reason", type(exc).__name__))
        outcome["win32_error"] = getattr(exc, "win32_error", None)
        write_json(directory / "host-error.json", outcome)
        return 125
    finally:
        if process:
            process.close()
        if job:
            job.close()  # This is not evidence of empty or OS-limit restoration.
        timer.cancel()


PS_BRIDGE = r'''param([string]$LaunchSpecB64, [string]$PythonPath, [string]$HostPath, [string]$Mode)
$ErrorActionPreference = 'Stop'
$spec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($LaunchSpecB64)) | ConvertFrom-Json
$hostInfo = @{version=$PSVersionTable.PSVersion.ToString(); edition=$PSVersionTable.PSEdition; pid=$PID} | ConvertTo-Json -Compress
[IO.File]::WriteAllText((Join-Path $spec.directory 'powershell-host.json'), $hostInfo)
$hostInfo = @{version=$PSVersionTable.PSVersion.ToString(); edition=$PSVersionTable.PSEdition; pid=$PID} | ConvertTo-Json -Compress
[IO.File]::WriteAllText((Join-Path $spec.directory 'powershell-host.json'), $hostInfo)
if ($Mode -eq 'baseline') {
    & "$env:SystemRoot\System32\cmd.exe" /d /s /c $spec.command
    exit $LASTEXITCODE
}
if ($Mode -ne 'managed') { exit 125 }
& $PythonPath $HostPath --launch-spec-b64 $LaunchSpecB64
exit $LASTEXITCODE
'''


def _console_driver(payload: str) -> int:
    """Run only inside a NEW_CONSOLE owned by this fixture invocation."""
    try:
        require_continuous_admission()
    except ContinuousAdmissionUnavailable:
        return 125
    spec = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    directory = Path(spec["directory"]).resolve(strict=True)
    authorization = json.loads((directory / "fixture-authorization.json").read_text("utf-8"))
    remaining = float(authorization["deadline_unix"]) - time.time()
    if (os.environ.get("SENTINEL_ADAPTIVE_WINDOWS_SPIKES") != "1"
            or authorization["token"] != spec["token"] or not 0 < remaining <= 120
            or ".resource-sentinel" in (part.casefold() for part in directory.parts)):
        return 125
    timer = threading.Timer(remaining, lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    native = _native()
    result = {"status": "failed", "signals_sent": 0, "mode": spec["mode"]}
    held = []
    shell = None
    try:
        native.require_supported_host()
        driver_identity = native.current_identity()
        initial = set(native.console_process_ids())
        if initial != {driver_identity["pid"]}:
            result.update(status="unsupported", reason="console_not_exclusively_owned_before_launch")
            return 125
        # The signal is ignored only by the test driver. The workload installs
        # its own observable SIGINT handler. No Ctrl+Break substitution is used.
        signal.signal(signal.SIGINT, lambda *_: None)
        # No redirection: this case verifies actual console stdio handles, in
        # addition to pipe/file/NUL cases elsewhere in the suite.
        shell = subprocess.Popen(spec["shell_args"], cwd=directory)
        shell_handle = native.ProcessHandle.open(shell.pid)
        held.append(shell_handle)
        fixture = wait_file(directory / "signal-handler-ready.json", 20)
        if fixture["stdio_isatty"] != [True, True, True]:
            result.update(status="unsupported", reason="console_standard_handles_not_preserved")
            return 125
        known = [driver_identity, shell_handle.identity(), fixture["identity"], fixture["parent_identity"]]
        if spec["mode"] == "managed":
            launch = wait_file(directory / "launch.json")
            known.extend((launch["wrapper_identity"], launch["root_identity"]))
        identities = {item["pid"]: item for item in known}
        attached = set(native.console_process_ids())
        if not {driver_identity["pid"], fixture["identity"]["pid"]}.issubset(attached) or not attached.issubset(identities):
            result.update(status="unsupported", reason="console_contains_unverified_process", attached_count=len(attached))
            return 125
        for pid in attached:
            handle = native.ProcessHandle.open(pid, identities[pid]["created_filetime_100ns"])
            held.append(handle)
            if handle.wait(0):
                result.update(status="unsupported", reason="console_identity_exited_before_signal")
                return 125
        # Recheck the whole console after holding all verified identities.
        if set(native.console_process_ids()) != attached:
            result.update(status="unsupported", reason="console_membership_changed_before_signal")
            return 125
        os.kill(0, signal.CTRL_C_EVENT)
        result["signals_sent"] = 1
        result["shell_exit_code"] = shell.wait(timeout=20)
        finished = wait_file(directory / "root.done.json", 10)
        result.update(status="observed", ctrl_c_received=finished.get("ctrl_c_received", False),
                      workload_identity=finished["identity"], verified_console_processes=len(attached))
        if spec["mode"] == "managed":
            result["root_outcome"] = wait_file(directory / "root-exit.json", 10)
        return 0
    except native.UnsupportedCapability as exc:
        result.update(status="unsupported", reason=exc.reason, win32_error=exc.win32_error)
        return 125
    except Exception as exc:
        result.update(reason=type(exc).__name__)
        return 125
    finally:
        # The bounded fixture remains responsible for its own deadline. No
        # fallback signal is sent and no process is killed after a failed probe.
        (directory / "stop").touch()
        try:
            if shell:
                shell.wait(timeout=10)
            until = time.monotonic() + 10
            while time.monotonic() < until:
                attached = set(native.console_process_ids())
                if attached == {os.getpid()}:
                    break
                time.sleep(0.05)
            result["cleanup_verified"] = set(native.console_process_ids()) == {os.getpid()}
        except Exception as exc:
            result.update(cleanup_verified=False, cleanup_error=type(exc).__name__)
        for handle in held:
            handle.close()
        write_json(directory / "console-result.json", result)
        timer.cancel()


class LaunchLengthContracts(unittest.TestCase):
    """Pure preflight contracts; these do not prove Windows support."""

    def test_transport_and_cmd_limits_are_independent(self):
        cmd = r"C:\Windows\System32\cmd.exe"
        python, host = r"C:\Python\python.exe", r"C:\Sentinel\host.py"
        with self.assertRaisesRegex(ValueError, "cmd_payload"):
            validate_launch_lengths("x" * CMD_LIMIT, "QQ==", cmd, python, host)
        with self.assertRaisesRegex(ValueError, "launch_payload_too_large"):
            validate_launch_lengths("exit 0", "A" * CREATE_PROCESS_LIMIT, cmd, python, host)
        validate_launch_lengths("exit 0", "QQ==", cmd, python, host)

    def test_utf16_count_includes_surrogate_pairs(self):
        self.assertEqual(utf16_units("a\U0001f4be"), 3)


@unittest.skipUnless(sys.platform == "win32" and os.environ.get("SENTINEL_ADAPTIVE_WINDOWS_SPIKES") == "1",
                     "Windows S2 not verified: explicit isolated spike opt-in required")
class WindowsLaunchCompatibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base = os.environ.get("SENTINEL_ADAPTIVE_SPIKE_DIR")
        if not base:
            raise unittest.SkipTest("S2 not verified: isolated SENTINEL_ADAPTIVE_SPIKE_DIR required")
        base_path = Path(base).resolve()
        if ".resource-sentinel" in (part.casefold() for part in base_path.parts):
            raise RuntimeError("production_directory_forbidden")
        cls.evidence = base_path / ("s2-" + uuid.uuid4().hex)
        cls.evidence.mkdir(parents=True, exist_ok=False)
        try:
            require_continuous_admission()
        except ContinuousAdmissionUnavailable as exc:
            write_json(cls.evidence / "admission-gate.json", {
                "status": "blocked", "reason": exc.reason,
                "cpu_control_writes": 0, "capability_allowlist_eligible": False,
            })
            raise
        cls.native = _native()
        try:
            cls.capability = cls.native.require_supported_host()
        except cls.native.UnsupportedCapability as exc:
            write_json(cls.evidence / "unsupported.json", {"phase": "P1-S2", "status": "unsupported",
                       "reason": exc.reason, "win32_error": exc.win32_error})
            raise unittest.SkipTest("S2 unsupported; Windows gate is NOT passed: " + str(exc.reason))
        candidates = [Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"]
        found = shutil.which("pwsh")
        if found:
            candidates.append(Path(found))
        bundled = Path.home() / ".cache/codex-runtimes/codex-primary-runtime/dependencies/native/powershell/pwsh.exe"
        if bundled.is_file():
            candidates.append(bundled)
        cls.hosts = list(dict.fromkeys(str(path.resolve()) for path in candidates if path.is_file()))
        if not cls.hosts:
            raise unittest.SkipTest("S2 unsupported: no installed PowerShell host")
        cls.bridge = cls.evidence / "thin bridge 測試.ps1"
        # BOM is required for Windows PowerShell 5.1's source-file decoding.
        cls.bridge.write_text(PS_BRIDGE, encoding="utf-8-sig")
        write_json(cls.evidence / "environment.json", {"phase": "P1-S2", "capability": cls.capability,
                   "host_names": [Path(host).name for host in cls.hosts],
                   "ctrl_c": "requires_separate_owned_console_probe_result",
                   "production_local_adapter": "not_invoked_fixture_topology_only"})

    def case_directory(self, name: str) -> tuple[Path, str]:
        # Every actual workload cwd, not only the outer PS bridge, exercises
        # both Unicode and spaces through CreateProcessW's lpCurrentDirectory.
        directory = self.evidence / (name[:28] + "-" + uuid.uuid4().hex[:12] + " 空白 測試")
        directory.mkdir()
        token = uuid.uuid4().hex
        write_json(directory / "fixture-authorization.json", {"token": token, "deadline_unix": time.time() + 115})
        return directory, token

    def command(self, directory: Path, token: str, *extra: str) -> str:
        # Only the synthetic fixture invocation is constructed here. The launch
        # host never tokenizes or reconstructs the user's cmd payload.
        return subprocess.list2cmdline([sys.executable, str(FIXTURE), "--directory", str(directory),
                                       "--token", token, "--api-root", str(ROOT), *extra])

    def launch_fixture(self, job, command: str, directory: Path, **handles):
        try:
            return self.native.launch_in_job(job, sys.executable, command, **handles)
        except self.native.LaunchOutcomeUnknown as exc:
            # Direct test launch sites have the same once-only boundary as the
            # thin host. Preserve and close the returned exact process handle.
            (directory / "stop").touch()
            try:
                exited = exc.process.wait(15)
                write_json(directory / "launch-unknown.json", {"root_launched": True,
                           "status": "launch_outcome_unknown", "root_observed_exited": exited})
            finally:
                exc.process.close()
            raise

    def host_args(self, host: str, directory: Path, token: str, command: str,
                  mode: str, observer: bool = False, console_fixture: bool = False) -> list[str]:
        spec = {"directory": str(directory), "token": token, "command": command,
                "observer_handshake": observer, "console_fixture": console_fixture}
        payload = encoded_spec(spec)
        cmd = str(Path(os.environ["SystemRoot"]) / "System32/cmd.exe")
        validate_launch_lengths(command, payload, cmd, sys.executable, str(Path(__file__).resolve()))
        result = [host, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                  "-File", str(self.bridge), "-LaunchSpecB64", payload, "-PythonPath", sys.executable,
                  "-HostPath", str(Path(__file__).resolve()), "-Mode", mode]
        if utf16_units(subprocess.list2cmdline(result)) + 1 > CREATE_PROCESS_LIMIT:
            raise ValueError("powershell_transport_too_large")
        return result

    def run_case(self, host: str, name: str, mode: str, extra: tuple[str, ...],
                 stdin: bytes = b"", transform=None) -> tuple[subprocess.CompletedProcess, dict, Path]:
        directory, token = self.case_directory(name + "-" + mode)
        command = self.command(directory, token, *extra)
        if transform:
            command = transform(command, directory)
        env = dict(os.environ, SENTINEL_S2_PERCENT="percent-value", SENTINEL_S2_BANG="bang-value")
        result = run_without_timeout_kill(self.host_args(host, directory, token, command, mode),
                                         input=stdin, timeout=120, cwd=directory, env=env)
        error = directory / "host-error.json"
        self.assertFalse(error.exists(), error.read_text("utf-8") if error.exists() else "")
        done = wait_file(directory / "root.done.json")
        if mode == "managed":
            self.assertTrue(done["job_membership"])
            metadata = wait_file(directory / "root-exit.json")
            self.assertTrue(metadata["root_launched"])
            self.assertIsNone(metadata["infrastructure_failure"])
            self.assertEqual(metadata["cpu_control"]["flags"] & 1, 0)
            self.assertEqual(metadata["root_exit_code"], result.returncode)
        write_json(directory / "summary.json", {"case": name, "mode": mode, "exit_code": result.returncode,
                   "host_name": Path(host).name, "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr),
                   "powershell_host": wait_file(directory / "powershell-host.json"),
                   "powershell_host": wait_file(directory / "powershell-host.json"),
                   "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                   "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(), "identity": done["identity"],
                   "job_membership": done["job_membership"]})
        return result, done, directory

    def test_each_host_cmd_semantics_stdio_and_exit_three_rounds(self):
        cases = [
            ("unicode-quotes", ("--mode", "io", "--literal", "Unicode 測試 Ω", "--literal", 'embedded"quote'), b""),
            ("stdin", ("--mode", "io", "--read-stdin"), b"stdin payload\r\nsecond line\r\n"),
            ("large-simultaneous", ("--mode", "io", "--large-bytes", "262144"), b""),
            ("quiet-0", ("--mode", "quiet", "--exit-code", "0"), b""),
            ("quiet-7", ("--mode", "quiet", "--exit-code", "7"), b""),
            ("child-125", ("--mode", "quiet", "--exit-code", "125"), b""),
        ]
        for host in self.hosts:
            for round_number in range(3):
                for name, extra, data in cases:
                    with self.subTest(host=Path(host).name, case=name, round=round_number):
                        legacy, before, _ = self.run_case(host, name, "baseline", extra, data)
                        managed, after, _ = self.run_case(host, name, "managed", extra, data)
                        self.assertEqual((managed.returncode, managed.stdout, managed.stderr),
                                         (legacy.returncode, legacy.stdout, legacy.stderr))
                        self.assertEqual(after["literals"], before["literals"])
                        self.assertEqual(after["stdin_hex"], before["stdin_hex"])
                        if name == "unicode-quotes":
                            self.assertEqual(after["literals"], ["Unicode 測試 Ω", 'embedded"quote'])
                        if name == "stdin":
                            self.assertEqual(bytes.fromhex(after["stdin_hex"]), data)
                        if name.startswith("quiet") or name == "child-125":
                            self.assertEqual((managed.stdout, managed.stderr), (b"", b""))
                            self.assertEqual(managed.returncode, int(extra[-1]))
                        if name == "large-simultaneous":
                            self.assertEqual(managed.stdout, b"O" * 262144)
                            self.assertEqual(managed.stderr, b"E" * 262144)

    def test_each_host_metacharacters_redirection_pipeline_three_rounds(self):
        def transform(command: str, directory: Path) -> str:
            (directory / "input.txt").write_bytes(b"redirect input\r\n")
            # All named files are synthetic and relative to an owned case dir.
            return (command + ' --literal "%SENTINEL_S2_PERCENT%" --literal "!SENTINEL_S2_BANG!"'
                    ' < input.txt > output.txt 2> error.txt & type output.txt | findstr /C:"stdout"'
                    ' & echo caret^^ ^& ^| ^> ^<')

        for host in self.hosts:
            for round_number in range(3):
                with self.subTest(host=Path(host).name, round=round_number):
                    extra = ("--mode", "io", "--read-stdin")
                    legacy, before, old = self.run_case(host, "metacharacters", "baseline", extra, transform=transform)
                    managed, after, new = self.run_case(host, "metacharacters", "managed", extra, transform=transform)
                    self.assertEqual((managed.returncode, managed.stdout, managed.stderr),
                                     (legacy.returncode, legacy.stdout, legacy.stderr))
                    self.assertEqual(after["literals"], ["percent-value", "!SENTINEL_S2_BANG!"])
                    self.assertEqual(after["literals"], before["literals"])
                    self.assertEqual(bytes.fromhex(after["stdin_hex"]), b"redirect input\r\n")
                    for file in ("output.txt", "error.txt"):
                        self.assertEqual((new / file).read_bytes(), (old / file).read_bytes())

    def test_each_host_fast_exit_twenty_rounds(self):
        for host in self.hosts:
            for round_number in range(20):
                with self.subTest(host=Path(host).name, round=round_number):
                    result, _, directory = self.run_case(host, "fast-exit", "managed", ("--mode", "quiet"))
                    self.assertEqual(result.returncode, 0)
                    self.assertEqual(wait_file(directory / "root-exit.json")["job_after_root"]["active_processes"], 0)

    def test_each_host_root_exit_preserves_child_twenty_rounds(self):
        for host in self.hosts:
            for round_number in range(20):
                with self.subTest(host=Path(host).name, round=round_number):
                    directory, token = self.case_directory("surviving-child")
                    command = self.command(directory, token, "--mode", "tree", "--seconds", "90", "--exit-code", "7")
                    process = subprocess.Popen(self.host_args(host, directory, token, command, "managed", True),
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               cwd=directory)
                    job = None
                    try:
                        spec = wait_file(directory / "expected-job.json")
                        job = self.native.OwnedJob.open(spec["name"], spec["nonce"])
                        (directory / "observer-ready").touch()
                        output, errors = process.communicate(timeout=120)
                        self.assertEqual((process.returncode, output, errors), (7, b"", b""))
                        root = wait_file(directory / "root-exit.json")
                        child = wait_file(directory / "child.ready.json")
                        self.assertTrue(child["job_membership"])
                        self.assertGreater(root["job_after_root"]["active_processes"], 0)
                        self.assertIn(child["identity"]["pid"], job.active_pids())
                        self.assertEqual(job.query_cpu()["flags"] & 1, 0)
                        # Positive survival evidence precedes voluntary release;
                        # a slow test observer cannot race an arbitrary 6s nap.
                        (directory / "stop").touch()
                        self.assertTrue(job.wait_empty(15), "child did not finish voluntarily")
                        self.assertEqual(job.accounting()["active_processes"], 0)
                        wait_file(directory / "child.done.json")
                        write_json(directory / "summary.json", {"case": "surviving-child", "round": round_number,
                                   "root_exit_code": 7, "root_exit_active": root["job_after_root"]["active_processes"],
                                   "child_identity": child["identity"], "job_empty_verified": True,
                                   "child_release": "observer_verified_then_voluntary_stop",
                                   "cpu_control": job.query_cpu()})
                    finally:
                        # Voluntary completion is the only cleanup; no workload
                        # terminate/kill call is used if an assertion fails.
                        (directory / "stop").touch()
                        if job:
                            job.wait_empty(15)
                            job.close()

    def test_null_stdio_rejected_before_launch_and_explicit_nul_supported(self):
        import msvcrt

        for missing in ("stdin_handle", "stdout_handle", "stderr_handle"):
            directory, token = self.case_directory("missing-stdio")
            job = self.native.OwnedJob.create()
            try:
                command = self.command(directory, token, "--mode", "quiet")
                with open(os.devnull, "rb") as read, open(os.devnull, "wb") as write:
                    handles = {"stdin_handle": msvcrt.get_osfhandle(read.fileno()),
                               "stdout_handle": msvcrt.get_osfhandle(write.fileno()),
                               "stderr_handle": msvcrt.get_osfhandle(write.fileno())}
                    handles[missing] = 0
                    with self.assertRaises((ValueError, OSError, self.native.UnsupportedCapability)):
                        self.launch_fixture(job, command, directory, **handles)
                self.assertEqual(job.accounting()["total_processes"], 0)
                self.assertFalse((directory / "root.ready.json").exists())
            finally:
                job.close()
        directory, token = self.case_directory("explicit-nul")
        job = self.native.OwnedJob.create()
        process = None
        try:
            write_json(directory / "expected-job.json", {"name": job.name, "nonce": job.nonce})
            with open(os.devnull, "rb") as read, open(os.devnull, "wb") as write:
                process = self.launch_fixture(job, self.command(directory, token, "--mode", "quiet"), directory,
                    stdin_handle=msvcrt.get_osfhandle(read.fileno()), stdout_handle=msvcrt.get_osfhandle(write.fileno()),
                    stderr_handle=msvcrt.get_osfhandle(write.fileno()))
                self.assertTrue(process.wait(20))
                self.assertEqual(process.exit_code(), 0)
            self.assertTrue(wait_file(directory / "root.done.json")["job_membership"])
            self.assertTrue(job.wait_empty(5))
        finally:
            if process:
                process.close()
            job.close()

    def test_cmd_oversize_rejected_by_managed_host_before_job_creation(self):
        directory, token = self.case_directory("oversize-command")
        command = self.command(directory, token, "--mode", "quiet") + " " * CMD_LIMIT
        payload = encoded_spec({"directory": str(directory), "token": token, "command": command})
        args = [sys.executable, str(Path(__file__).resolve()), "--launch-spec-b64", payload]
        # This case fits the native transport but exceeds the independent cmd
        # boundary. Deliberately bypass only the test caller's redundant check
        # to exercise the managed host's mandatory prelaunch validation itself.
        self.assertLess(utf16_units(subprocess.list2cmdline(args)) + 1, CREATE_PROCESS_LIMIT)
        result = run_without_timeout_kill(args, stdin=subprocess.DEVNULL, timeout=20, cwd=directory)
        self.assertEqual(result.returncode, 125)
        outcome = wait_file(directory / "host-error.json")
        self.assertEqual(outcome["infrastructure_failure"], "cmd_payload_too_large_or_invalid")
        self.assertFalse(outcome["root_launched"])
        self.assertFalse((directory / "expected-job.json").exists())
        self.assertFalse((directory / "root.ready.json").exists())

    def test_each_host_ctrl_c_in_owned_console_three_rounds(self):
        if not hasattr(self.native, "console_process_ids"):
            self.skipTest("S2 Ctrl+C unverified: isolated console membership API unavailable")
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startup.wShowWindow = 0
        for host in self.hosts:
            for round_number in range(3):
                observed = {}
                for mode in ("baseline", "managed"):
                    unsupported = None
                    with self.subTest(host=Path(host).name, round=round_number, mode=mode):
                        directory, token = self.case_directory("ctrl-c-" + mode)
                        command = self.command(directory, token, "--mode", "signal", "--seconds", "60", "--exit-code", "130")
                        args = self.host_args(host, directory, token, command, mode, console_fixture=True)
                        driver_spec = {"directory": str(directory), "token": token, "mode": mode, "shell_args": args}
                        process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                                   "--console-driver-b64", encoded_spec(driver_spec)], cwd=directory,
                                                   creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=startup)
                        process.wait(timeout=120)
                        outcome = wait_file(directory / "console-result.json")
                        if outcome["status"] == "unsupported":
                            unsupported = outcome["reason"]
                        else:
                            self.assertEqual(outcome["status"], "observed", outcome)
                            self.assertEqual(outcome["signals_sent"], 1)
                            self.assertTrue(outcome["ctrl_c_received"])
                            if mode == "managed":
                                self.assertTrue(outcome["root_outcome"]["root_launched"])
                                self.assertEqual(outcome["root_outcome"]["cpu_control"]["flags"] & 1, 0)
                            observed[mode] = outcome
                        self.assertTrue(outcome["cleanup_verified"], outcome)
                    # SkipTest inside subTest would be caught there and leave a
                    # missing result that later becomes an unrelated KeyError.
                    if unsupported:
                        self.skipTest("S2 Ctrl+C unsupported; no host promotion: " + unsupported)
                if set(observed) == {"managed", "baseline"}:
                    self.assertEqual(observed["managed"]["shell_exit_code"], observed["baseline"]["shell_exit_code"])

    def test_collector_timeout_only_reaches_owned_descendants(self):
        import msvcrt

        collector_dir, collector_token = self.case_directory("collector-timeout")
        manager_dir, manager_token = self.case_directory("independent-manager")
        collector_job = self.native.OwnedJob.create()
        manager_job = self.native.OwnedJob.create()
        collector = manager = child = None
        try:
            for directory, job in ((collector_dir, collector_job), (manager_dir, manager_job)):
                write_json(directory / "expected-job.json", {"name": job.name, "nonce": job.nonce})
            with open(os.devnull, "rb") as stdin, open(os.devnull, "wb") as stdout:
                handles = {"stdin_handle": msvcrt.get_osfhandle(stdin.fileno()),
                           "stdout_handle": msvcrt.get_osfhandle(stdout.fileno()),
                           "stderr_handle": msvcrt.get_osfhandle(stdout.fileno())}
                # Both roots are created by this test parent, in distinct owned
                # uncapped Jobs. Neither is an actual collector or guardian.
                manager = self.launch_fixture(manager_job,
                    self.command(manager_dir, manager_token, "--mode", "leaf", "--seconds", "60"), manager_dir, **handles)
                collector = self.launch_fixture(collector_job,
                    self.command(collector_dir, collector_token, "--mode", "collector", "--seconds", "60"), collector_dir, **handles)
                tree = wait_file(collector_dir / "root.children.json")
                sibling = wait_file(manager_dir / "root.ready.json")
                child_ready = wait_file(collector_dir / "child.ready.json")
                self.assertEqual(tree["identity"], collector.identity())
                self.assertEqual(sibling["identity"], manager.identity())
                self.assertEqual(child_ready["parent_pid"], collector.pid)
                self.assertEqual(sibling["parent_pid"], os.getpid())
                self.assertTrue(child_ready["job_membership"])
                child = self.native.ProcessHandle.open(tree["child_identity"]["pid"],
                            tree["child_identity"]["created_filetime_100ns"])
                self.assertFalse(collector.wait(0))
                self.assertFalse(child.wait(0))
                self.assertFalse(manager.wait(0))
                self.assertEqual(set(collector_job.active_pids()), {collector.pid, child.pid})
                self.assertEqual(set(manager_job.active_pids()), {manager.pid})
                self.assertNotIn(manager.pid, collector_job.active_pids())
                taskkill = Path(os.environ["SystemRoot"]) / "System32" / "taskkill.exe"
                # This is the *fault injector* reproducing the existing
                # collector's timeout. Exact held identities and the complete
                # fixture subtree were checked above; no scheduler kill path is
                # added and no runtime/agent PID can be supplied by the caller.
                injection = run_without_timeout_kill([str(taskkill), "/PID", str(collector.pid), "/T", "/F"],
                                                    timeout=15)
                self.assertEqual(injection.returncode, 0)
                self.assertTrue(collector.wait(10))
                self.assertTrue(child.wait(10))
                self.assertTrue(collector_job.wait_empty(5))
                self.assertFalse(manager.wait(0), "independent fixture was affected by collector subtree timeout")
                self.assertEqual(manager_job.query_cpu()["flags"] & 1, 0)
                write_json(collector_dir / "summary.json", {"case": "collector-timeout", "scope": "fixture_topology_only",
                           "collector_identity": collector.identity(), "child_identity": child.identity(),
                           "independent_identity": manager.identity(), "child_new_process_group_did_not_detach": True,
                           "collector_job_empty_verified": True, "independent_manager_survived": True,
                           "production_local_adapter_invoked": False, "production_supervisor_validated": False})
        finally:
            previous_error = sys.exception()
            (collector_dir / "stop").touch()
            (manager_dir / "stop").touch()
            cleanup = {"collector_empty": False, "independent_manager_empty": False}
            try:
                cleanup["collector_empty"] = collector_job.wait_empty(15)
                cleanup["independent_manager_empty"] = manager_job.wait_empty(15)
                cleanup["collector_cpu_control"] = collector_job.query_cpu()
                cleanup["independent_cpu_control"] = manager_job.query_cpu()
            except Exception as exc:
                cleanup["error"] = type(exc).__name__
            finally:
                write_json(collector_dir / "cleanup.json", cleanup)
                for process in (collector, manager, child):
                    if process:
                        process.close()
                collector_job.close()
                manager_job.close()
            cleanup_verified = (cleanup["collector_empty"] and cleanup["independent_manager_empty"]
                                and "error" not in cleanup
                                and cleanup["collector_cpu_control"]["flags"] & 1 == 0
                                and cleanup["independent_cpu_control"]["flags"] & 1 == 0)
            if not cleanup_verified:
                if previous_error is not None:
                    previous_error.add_note("S2 collector fixture cleanup remains unverified; see cleanup.json")
                else:
                    self.fail("S2 collector fixture cleanup remains unverified; see cleanup.json")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--launch-spec-b64":
        raise SystemExit(_launch_host(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--console-driver-b64":
        raise SystemExit(_console_driver(sys.argv[2]))
    unittest.main()
