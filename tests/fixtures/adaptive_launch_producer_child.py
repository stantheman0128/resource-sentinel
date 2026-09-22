"""Synthetic S2 workload and instrumented *real* WrapperHost.

Only the workload has a self-imposed deadline. The wrapper uses normal real
admission and retained recovery; a timer must never discard that custody.
The authorization file limits fixture I/O and is not admission authority.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def authorize(directory, token):
    directory = Path(directory).resolve(strict=True)
    if ".resource-sentinel" in {part.casefold() for part in directory.parts}:
        raise ValueError("s2_production_evidence_directory_forbidden")
    value = json.loads((directory / "fixture-authorization.json").read_text("utf-8"))
    if value["token"] != token or not 0 < value["deadline_unix"] - time.time() <= 120:
        raise ValueError("s2_fixture_authorization_expired")
    return directory, value


def wait_json(path, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if path.exists():
            return json.loads(path.read_text("utf-8"))
        time.sleep(.02)
    raise RuntimeError("s2_fixture_evidence_deadline")


def tick():
    from tests.windows.adaptive_win32 import interrupt_time_100ns
    return interrupt_time_100ns()


def workload(args):
    from tests.windows import adaptive_win32 as native
    from sentinel.adaptive.native_job import NativeJob, JobAccess
    directory, authorization = authorize(args.directory, args.token)
    current = native.ProcessHandle.open_current()
    record = {"identity": current.identity(), "parent_pid": current.parent_pid(),
              "started_tick": tick(), "membership": None, "literals": args.literal,
              "stdio_isatty": [stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)]}
    parent = native.ProcessHandle.open(record["parent_pid"])
    try:
        record["parent_identity"] = parent.identity()
    finally:
        parent.close()
    if args.managed:
        expected = wait_json(directory / "expected-job.json")
        job = NativeJob.open(expected["name"], expected["nonce"], expected["logon_id"], access=JobAccess.QUERY)
        try:
            record["membership"] = current.is_in_job(job)
        finally:
            job.close()
        if record["membership"] is not True:
            raise RuntimeError("s2_user_code_started_outside_job")
    current.close()
    write(directory / (args.label + ".ready.json"), record)
    remaining = authorization["deadline_unix"] - time.time()
    timer = threading.Timer(max(.001, remaining), lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    try:
        if args.mode == "io":
            data = sys.stdin.buffer.read(1048577) if args.read_stdin else b""
            if len(data) > 1048576:
                raise ValueError("s2_stdin_limit")
            record["stdin_hex"] = data.hex()
            if args.large:
                def emit(stream, value):
                    for _ in range(64):
                        stream.write(value * 4096)
                        stream.flush()
                threads = [threading.Thread(target=emit, args=(sys.stdout.buffer, b"O")),
                           threading.Thread(target=emit, args=(sys.stderr.buffer, b"E"))]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            else:
                sys.stdout.buffer.write("stdout: 測試 Ω\n".encode("utf-8") + data)
                sys.stderr.buffer.write("stderr: 測試 Ω\n".encode("utf-8"))
                sys.stdout.buffer.flush()
                sys.stderr.buffer.flush()
        elif args.mode in ("tree", "collector"):
            command = [sys.executable, str(Path(__file__).resolve()), "workload", "--directory", str(directory),
                       "--token", args.token, "--mode", "leaf", "--label", "child"]
            if args.managed:
                command.append("--managed")
            subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL,
                             creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if args.mode == "collector" else 0)
            child = wait_json(directory / "child.ready.json")
            record["child_identity"] = child["identity"]
            write(directory / "tree-ready.json", record)
            if args.mode == "collector":
                while not (directory / "stop").exists():
                    time.sleep(.025)
        elif args.mode == "signal":
            received = threading.Event()
            signal.signal(signal.SIGINT, lambda *_: received.set())
            write(directory / "signal-ready.json", record)
            while not received.is_set() and not (directory / "stop").exists():
                received.wait(.025)
            record["ctrl_c_received"] = received.is_set()
            if not received.is_set():
                return 124
        elif args.mode == "leaf":
            while not (directory / "stop").exists():
                time.sleep(.025)
        record["ended_tick"] = tick()
        write(directory / (args.label + ".done.json"), record)
        return args.exit_code
    finally:
        timer.cancel()


def wrapper(payload):
    from sentinel.adaptive import wrapper_host, native_launcher
    from sentinel.adaptive.contracts import Priority, ResourceDemand, Role
    from sentinel.adaptive.launcher import ManagedLauncher
    spec = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    directory, _ = authorize(spec["directory"], spec["token"])
    events = directory / "wrapper-events.jsonl"
    def emit(value):
        with events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(dict(value, observed_tick=tick())) + "\n")
    wrapper_host.emit = emit  # fixture process only; do not pollute workload stdout.
    raw = {"started_tick": tick(), "launches": 0, "native_calls": [], "infrastructure_failure": None}
    def create(job, application, command_line, **kwargs):
        write(directory / "expected-job.json", {"name": job.name, "nonce": job.nonce,
                                               "logon_id": job.logon_sid})
        raw["launches"] += 1
        raw["create_started_tick"] = tick()
        result = native_launcher.launch_in_job(job, application, command_line, **kwargs)
        raw["create_returned_tick"] = tick()
        raw["root_identity"] = result.identity()
        provenance = getattr(result, "launch_provenance", None)
        if provenance is not None:
            raw["launch_provenance"] = provenance.to_dict()
        raw["native_calls"].append("CreateProcessW:JOB_LIST:HANDLE_LIST")
        write(directory / "wrapper-launch.json", raw)
        return result
    def factory(*args, **kwargs):
        return ManagedLauncher(*args, **kwargs, launch=create)
    class ObservedHost(wrapper_host.WrapperHost):
        def _wait(self):
            observation = super()._wait()
            raw["root_exit_tick"] = tick()
            raw["root_exit_code"] = observation.exit_code
            accounting = self.launcher.job.accounting()
            raw["live_child_count_after_root"] = accounting.active_processes
            raw["members_after_root"] = list(self.launcher.job.active_pids())
            write(directory / "root-exit.json", raw)
            if spec["case"] == "root_child_survival":
                # Release only after the parent observer saw positive survival.
                wait_json(directory / "release-child.json")
                (directory / "stop").touch()
            until = time.monotonic() + 20
            while time.monotonic() < until:
                count = self.launcher.job.accounting().active_processes
                members = self.launcher.job.active_pids()
                if count == 0 and not members:
                    break
                time.sleep(.025)
            else:
                raise RuntimeError("s2_job_empty_deadline")
            control = self.launcher.job.query_cpu()
            raw.update(cpu_flags=control.flags, active_processes=count, job_empty_tick=tick(),
                       execution_id=self.launcher.execution_id)
            if control.flags & 1:
                raise RuntimeError("s2_unexpected_cpu_restriction")
            return observation
    guardian = spec["guardian"]
    host = ObservedHost(data_dir=spec["data_dir"], command=spec["command"], cwd=str(directory),
        repo_identifier="sentinel-native-s2", role=Role.BACKGROUND, priority=Priority.P2,
        requested=ResourceDemand(1.0, 256 * 1024**2, 256 * 1024**2, 0),
        guardian_epoch=guardian["epoch"], guardian_pid=guardian["pid"],
        guardian_created_filetime_100ns=int(guardian["birth"]),
        endpoint_instance_id=guardian["endpoint_instance_id"], launcher_factory=factory,
        max_wait_sec=90)
    result = 125
    previous_stdin = saved_stdin_fd = None
    if spec.get("probe_null_stdio"):
        # A real NULL standard handle in this isolated wrapper only. Restore
        # it after the production preflight, never substitute a fake backend.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetStdHandle.restype = ctypes.c_void_p
        kernel.SetStdHandle.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
        previous_stdin = kernel.GetStdHandle(ctypes.c_ulong(-10 & 0xffffffff))
        if not kernel.SetStdHandle(ctypes.c_ulong(-10 & 0xffffffff), None):
            raise ctypes.WinError(ctypes.get_last_error())
        # WrapperHost reads the CRT fd, not GetStdHandle. Invalidate that same
        # actual fd as well; merely replacing the OS selector would leave a
        # valid CRT pipe and would not exercise the intended prelaunch guard.
        saved_stdin_fd = os.dup(0)
        os.close(0)
    # Ctrl+C remains native workload behavior. The fixture wrapper records the
    # request without raising through its retained ownership publication points.
    with wrapper_host._owned_interrupts(host):
        try:
            result = host.run()
        except BaseException as error:
            raw["infrastructure_failure"] = getattr(error, "reason", type(error).__name__)
            raw["infrastructure_detail"] = getattr(error, "detail", None)
            host._recovering = True
            host._note_recovery_error(error)
            (directory / "stop").touch()
            host.settle_release()
        finally:
            if previous_stdin is not None:
                import msvcrt
                if saved_stdin_fd is not None:
                    os.dup2(saved_stdin_fd, 0)
                    os.close(saved_stdin_fd)
                if not kernel.SetStdHandle(ctypes.c_ulong(-10 & 0xffffffff), msvcrt.get_osfhandle(0)):
                    raise ctypes.WinError(ctypes.get_last_error())
            raw.update(ended_tick=tick(), host_exit_code=result,
                       local_cleanup_closed=bool(host.launcher is None or host.launcher._closed))
            write(directory / "wrapper-result.json", raw)
    return result


class _ConsoleCustody:
    """Keep the original shell/console owners until positively discharged.

    This is an in-process fixture owner, never a PID adoption/recovery token.
    Observation or native-close ambiguity is sticky: no second Close and no
    ordinary driver exit can turn that ambiguity into successful cleanup.
    """
    def __init__(self, directory, native, held, files):
        self.directory, self.native = directory, native
        self.held, self.files = held, files
        self.shell = None
        self.creation_started = self.console_verified = False
        self.settled = self.quarantined = False
        self.remaining = None
        self.errors = {}
        self._closed = set()
        self._closing = None
        self._stop_requested = False

    def remember(self, category, error):
        # Retain original exceptions, including any attached partial owner.
        # Each fixed boundary contributes at most its first unknown result.
        self.errors.setdefault(category, error)

    def _unknown(self, category, error):
        self.remember(category, error)
        self.quarantined = True
        return False

    def step(self):
        if self.settled:
            return True
        if self.quarantined:
            return False
        if self._closing is not None:
            return self._unknown("close", (self._closing, RuntimeError("s2_console_close_ack_unknown")))
        if not self._stop_requested:
            try:
                (self.directory / "stop").touch()
                self._stop_requested = True
            except BaseException as error:
                self.remember("stop_publication", error)
        if self.creation_started and self.shell is None:
            return self._unknown("creation", RuntimeError("s2_console_creation_unknown"))
        # A preflight rejection before any child creation owns no new console
        # member. Once creation begins, only the same console can prove empty.
        if not self.console_verified and not self.creation_started:
            self.settled = not self.held and not self.files
            return self.settled
        try:
            code = None if self.shell is None else self.shell.poll()
            if self.shell is not None and code is not None and type(code) is not int:
                raise RuntimeError("s2_shell_exit_unverified")
            members = self.native.console_process_ids()
            if (not members or any(type(pid) is not int or pid <= 0 for pid in members)
                    or len(set(members)) != len(members) or os.getpid() not in members):
                raise RuntimeError("s2_original_console_unverified")
            self.remaining = members
        except BaseException as error:
            return self._unknown("observation", error)
        if (self.shell is not None and code is None) or set(members) != {os.getpid()}:
            return False
        # Shell exit alone is insufficient: surviving descendants retain the
        # owned console. Close originals only after both positive observations.
        owners = [*self.held, *self.files]
        if self.shell is not None:
            owners.extend(stream for stream in (self.shell.stdin, self.shell.stdout, self.shell.stderr)
                          if stream is not None)
            handle = getattr(self.shell, "_handle", None)
            if handle is None:
                return self._unknown("creation_handle", RuntimeError("s2_shell_creation_handle_missing"))
            owners.append(handle)
        for owner in owners:
            if id(owner) in self._closed:
                continue
            # Publish the attempted owner before the native/file close. A
            # failed call stays quarantined and is never retried blindly.
            self._closing = owner
            try:
                (owner.Close if owner is getattr(self.shell, "_handle", None) else owner.close)()
            except BaseException as error:
                return self._unknown("close", (owner, error))
            self._closed.add(id(owner))
            self._closing = None
        self.settled = True
        return True

    def finish(self, raw, publish):
        """Remain resident through live children and failed evidence writes."""
        published = set()
        while True:
            try:
                complete = self.step()
                raw["cleanup_verified"] = complete
                raw["remaining_console_pids"] = self.remaining
                if not complete:
                    raw["cleanup_unverified"] = True
                if self.quarantined:
                    raw["error"] = "s2_console_cleanup_unknown"
                state = (complete, self.quarantined)
                if state not in published:
                    published.add(state)
                    try:
                        raw["ended_tick"] = tick()
                        publish()
                    except BaseException as error:
                        self.remember("evidence", error)
                        raw["error"] = "s2_console_evidence_write_failed"
                if complete:
                    return
                time.sleep(.25)
            except BaseException as error:
                self.remember("resident_interrupt", error)
                raw["error"] = "s2_console_cleanup_interrupted"


def console_driver(payload):
    """Stable hidden-console profile for every S2 case, with optional Ctrl+C."""
    from tests.windows import adaptive_win32 as native
    spec = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    directory, _ = authorize(spec["directory"], spec["token"])
    profile = spec.get("stdio_profile", "pipes")
    send_signal = spec.get("signal", False)
    if profile not in {"pipes", "null", "console"} or type(send_signal) is not bool:
        raise ValueError("s2_driver_profile_invalid")
    data = base64.b64decode(spec.get("input_b64", ""), validate=True)
    if len(data) > 1048576:
        raise ValueError("s2_driver_input_limit")
    raw = {"signals_sent": 0, "started_tick": tick(), "stdio_profile": profile}
    held, files, shell = [], [], None
    custody = _ConsoleCustody(directory, native, held, files)
    output = errors = b""
    try:
        initial = set(native.console_process_ids())
        if initial != {os.getpid()}:
            raise RuntimeError("s2_console_not_exclusively_owned")
        custody.console_verified = True
        signal.signal(signal.SIGINT, lambda *_: None)
        if profile == "pipes":
            streams = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elif profile == "null":
            streams = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            files.append(open("CONIN$", "rb", buffering=0))
            files.append(open("CONOUT$", "wb", buffering=0))
            streams = dict(stdin=files[0], stdout=files[1], stderr=files[1])
        custody.creation_started = True
        shell = subprocess.Popen(spec["shell_args"], cwd=directory, **streams)
        custody.shell = shell
        if send_signal:
            shell_handle = native.ProcessHandle.open(shell.pid)
            held.append(shell_handle)
            fixture = wait_json(directory / "signal-ready.json", 30)
            if fixture["stdio_isatty"] != [profile == "console"] * 3:
                raise RuntimeError("s2_console_stdio_not_preserved")
            # Only this fixture's exact native ancestry can authorize a signal.
            process = native.ProcessHandle.open(fixture["identity"]["pid"], fixture["identity"]["created_filetime_100ns"])
            identities = {os.getpid(): native.current_identity()}
            child_birth = None
            for _ in range(12):
                held.append(process)
                identity = process.identity()
                if process.wait(0) or (child_birth is not None and int(identity["created_filetime_100ns"]) > child_birth):
                    raise RuntimeError("s2_console_ancestor_unverified")
                identities[identity["pid"]] = identity
                if identity["pid"] == os.getpid():
                    break
                child_birth = int(identity["created_filetime_100ns"])
                process = native.ProcessHandle.open(process.parent_pid())
            else:
                raise RuntimeError("s2_console_ancestry_not_owned")
            attached = set(native.console_process_ids())
            if not attached.issubset(identities) or fixture["identity"]["pid"] not in attached:
                raise RuntimeError("s2_console_has_unverified_members")
            if set(native.console_process_ids()) != attached:
                raise RuntimeError("s2_console_membership_changed")
            # Group 0 is solely this freshly created, fully verified console.
            os.kill(0, signal.CTRL_C_EVENT)
            raw["signals_sent"] = 1
            raw["verified_identities"] = list(identities.values())
        output, errors = shell.communicate(input=data if profile == "pipes" else None, timeout=95)
        raw["shell_exit_code"] = shell.returncode
        if send_signal:
            finished = wait_json(directory / "root.done.json")
            raw["ctrl_c_received"] = finished.get("ctrl_c_received") is True
    except BaseException as error:
        custody.remember("primary", error)
        raw["error"] = getattr(error, "reason", type(error).__name__)
    finally:
        # Capture a returned original even if interrupted before assignment to
        # the owner. Missing creation outcome stays an explicit quarantine.
        if shell is not None:
            custody.shell = shell
        def publish():
            write(directory / "console-result.json", raw)
            (directory / "driver-stdout.bin").write_bytes(output or b"")
            (directory / "driver-stderr.bin").write_bytes(errors or b"")
        custody.finish(raw, publish)
    return 0 if not raw.get("error") and raw.get("cleanup_verified") and (not send_signal or raw.get("ctrl_c_received")) else 125


def main(argv=None):
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="action", required=True)
    for name in ("wrapper", "console"):
        modes.add_parser(name).add_argument("payload")
    work = modes.add_parser("workload")
    work.add_argument("--directory", required=True)
    work.add_argument("--token", required=True)
    work.add_argument("--mode", choices=("quiet", "io", "tree", "leaf", "signal", "collector"), default="quiet")
    work.add_argument("--label", choices=("root", "child"), default="root")
    work.add_argument("--managed", action="store_true")
    work.add_argument("--literal", action="append", default=[])
    work.add_argument("--read-stdin", action="store_true")
    work.add_argument("--large", action="store_true")
    work.add_argument("--exit-code", type=int, choices=(0, 7, 125, 130), default=0)
    args = parser.parse_args(argv)
    return wrapper(args.payload) if args.action == "wrapper" else console_driver(args.payload) if args.action == "console" else workload(args)


if __name__ == "__main__":
    raise SystemExit(main())
