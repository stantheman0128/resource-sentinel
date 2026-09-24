"""Synthetic S2 workload and instrumented *real* WrapperHost.

Only the workload has a self-imposed deadline. The wrapper uses normal real
admission and retained recovery; a timer must never discard that custody.
The authorization file limits fixture I/O and is not admission authority.
"""
from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import threading
import time

_SOURCE_BOOTSTRAP = None
_OBSERVER_OPEN_CUSTODY = []


class S2ObserverOpenPending(RuntimeError):
    def __init__(self, held, error):
        self.original_observers = tuple(held)
        self.native_uncertainties = ((error.owner, error),)
        super().__init__("s2_native_observer_open_cleanup_unknown")


def _open_observer(native, held, pid, birth=None):
    try:
        process = native.ProcessHandle.open(pid, birth)
    except native.RetainedProcessOpenError as error:
        # Retain both earlier successful observers and this original partial
        # owner. Its failed close must never be retried as ordinary cleanup.
        held.append(error.owner)
        pending = S2ObserverOpenPending(held, error)
        _OBSERVER_OPEN_CUSTODY.append(pending)
        raise pending from error
    held.append(process)  # Before identity reads, logging or the next open.
    return process


def _retain_observer_open_failure(error):
    if not any(item is error for item in _OBSERVER_OPEN_CUSTODY):
        _OBSERVER_OPEN_CUSTODY.append(error)
    # There is no positive close proof for this original native owner. Keep
    # the fixture alive and idle; neither a deadline nor Ctrl+C releases it.
    while True:
        try:
            time.sleep(.25)
        except BaseException:
            pass


def _load_bootstrap():
    """Read the exact stdlib-only bootstrap without any ambient repo import."""
    path = Path(__file__).parents[1] / "windows" / "adaptive_producer_bootstrap.py"
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("s2_bootstrap_path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise RuntimeError("s2_bootstrap_redirected")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= 1024 * 1024:
        raise RuntimeError("s2_bootstrap_file_invalid")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(1024 * 1024 + 1)
        closed = os.fstat(stream.fileno())
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def signature(info, names):
        return tuple(getattr(info, key, None) for key in names)
    if (len(raw) != before.st_size or signature(before, (*fields, "st_ctime_ns")) !=
            signature(after, (*fields, "st_ctime_ns")) or signature(opened, (*fields, "st_ctime_ns")) !=
            signature(closed, (*fields, "st_ctime_ns")) or signature(before, fields) != signature(opened, fields)):
        raise RuntimeError("s2_bootstrap_source_changed")
    name = "_sentinel_producer_bootstrap"
    if name in sys.modules:
        raise RuntimeError("s2_bootstrap_preloaded")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


def assert_source(value):
    """Verify original executed source before native work; pins grant nothing."""
    if _SOURCE_BOOTSTRAP is None:
        raise RuntimeError("s2_original_child_bootstrap_required")
    return _SOURCE_BOOTSTRAP.verify_pin(value)


def _decode_pin(value):
    if type(value) is not str or not 0 < len(value) <= 16384:
        raise ValueError("s2_source_pin_invalid")
    return json.loads(base64.b64decode(value, validate=True).decode("utf-8"))


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
    assert_source(_decode_pin(args.source_pin))
    from tests.windows import adaptive_win32 as native
    from sentinel.adaptive.native_job import NativeJob, JobAccess
    directory, authorization = authorize(args.directory, args.token)
    held = []
    current = _open_observer(native, held, os.getpid())
    record = {"identity": current.identity(), "parent_pid": current.parent_pid(),
              "started_tick": tick(), "membership": None, "literals": args.literal,
              "stdio_isatty": [stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)]}
    parent = _open_observer(native, held, record["parent_pid"])
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
            assert_source(_decode_pin(args.source_pin))
            command = [sys.executable, "-I", str(Path(__file__).resolve()), "--source-pin", args.source_pin,
                       "workload", "--directory", str(directory),
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


class _WrapperStdinSelector:
    """Restore the selector to the newly restored CRT fd, not a closed value."""
    def __init__(self, kernel, descriptor_api, selector):
        self.kernel, self.descriptor_api, self.selector = kernel, descriptor_api, selector

    def __call__(self):
        current = self.descriptor_api.get_osfhandle(0)
        if type(current) is not int or current <= 0:
            raise RuntimeError("s2_stdin_restored_descriptor_unverified")
        if not self.kernel.SetStdHandle(self.selector, current):
            raise RuntimeError("s2_stdin_selector_restore_failed")
        if self.kernel.GetStdHandle(self.selector) != current:
            raise RuntimeError("s2_stdin_selector_restore_unverified")


class _WrapperCustody:
    """Retain the original fixture host through failures in its observations.

    The production host/launcher performs release. This owner never reconstructs
    either object, reopens a PID, or turns a diagnostic failure into cleanup proof.
    """
    def __init__(self, directory, raw):
        self.directory, self.raw = directory, raw
        self.host = self.native_process = self.native_error = None
        self.constructed = self.create_attempted = self.host_settled = False
        self.native_transfer_unknown = False
        self.errors, self.cleanup = {}, []
        self._stop_attempted = False

    def construct(self, host_type, **arguments):
        if self.host is not None:
            raise RuntimeError("s2_wrapper_constructor_already_attempted")
        # The known Python host has no special __new__. Register the partial
        # original before __init__; a failed constructor is an explicit hold.
        self.host = object.__new__(host_type)
        host_type.__init__(self.host, **arguments)
        self.constructed = True
        return self.host

    def observe_launch(self, native, job, application, command_line, observe, **arguments):
        if self.create_attempted:
            raise RuntimeError("s2_wrapper_create_already_attempted")
        self.create_attempted = True
        try:
            original = native.launch_in_job(job, application, command_line, **arguments)
        except BaseException as error:
            # Native failures can themselves contain partial CreatedProcess
            # custody. Preserve their exact typed transfer to ManagedLauncher.
            self.native_error = error
            try:
                self.native_process = getattr(error, "native_launch_owner", None)
            except BaseException as diagnostic:
                self.native_transfer_unknown = True
                self.errors.setdefault("native_owner_observation", diagnostic)
            raise
        self.native_process = original
        try:
            observe(original)
        except BaseException as error:
            self.errors.setdefault("launch_observation", error)
            # ManagedLauncher consumes .process and .native_launch_owner from
            # this exact production exception, including BaseException causes.
            raise native.LaunchOutcomeUnknown(original, error) from error
        return original

    def failure(self, error, category="primary"):
        self.errors.setdefault(category, error)
        if self.raw.get("infrastructure_failure") is None:
            self.raw["infrastructure_failure"] = type(error).__name__
            for attribute, key in (("reason", "infrastructure_failure"),
                                   ("detail", "infrastructure_detail")):
                try:
                    value = getattr(error, attribute, None)
                    if type(value) is str and value:
                        self.raw[key] = value
                except BaseException as diagnostic:
                    self.errors.setdefault("diagnostic_" + attribute, diagnostic)
        if self.host is not None:
            try:
                self.host._recovering = True
                self.host._note_recovery_error(error)
            except BaseException as diagnostic:
                self.errors.setdefault("host_diagnostic", diagnostic)

    def step_host(self):
        if self.host_settled:
            return True
        if self.host is None:
            if self.create_attempted or self.native_process is not None or self.native_error is not None:
                return False
            self.host_settled = True  # No host construction was attempted.
            return True
        if not self.constructed:
            return False  # Keep the partial original; no inferred no-effect exit.
        receipt = self.host.settle_release(max_iterations=1)
        if self.native_transfer_unknown:
            return False
        launcher = self.host.launcher
        if receipt is None:
            complete = (launcher is None and not self.create_attempted and
                        self.host._construction_unknown is None)
        else:
            complete = (type(receipt) is dict and receipt.get("settled") is True and
                        (receipt.get("closed") is True or receipt.get("guardian_handoff") is True) and
                        launcher is not None and launcher._closed is True)
        # A guardian receipt cannot close this process's original native owner.
        if self.native_process is not None and self.native_process._closed is not True:
            complete = False
        if complete:
            self.host_settled = True
        return complete

    def finish_host(self):
        while not self.host_settled:
            try:
                if self.errors and not self._stop_attempted:
                    self._stop_attempted = True
                    try:
                        (self.directory / "stop").touch()
                    except BaseException as error:
                        self.failure(error, "stop_publication")
                if self.step_host():
                    return
            except BaseException as error:
                self.failure(error, "recovery")
            try:
                time.sleep(.05)
            except BaseException as error:
                self.failure(error, "recovery_interrupt")

    def defer_cleanup(self, name, action):
        self.cleanup.append({"name": name, "action": action, "state": "pending"})

    def step_cleanup(self):
        if not self.host_settled:
            return False
        for item in self.cleanup:
            if item["state"] == "closed":
                continue
            if item["state"] != "pending":
                return False  # Unknown native/file close is never retried.
            item["state"] = "calling"
            try:
                item["action"]()
            except BaseException as error:
                item["state"] = "unknown"
                self.failure(error, "cleanup_" + item["name"])
                return False
            item["state"] = "closed"
        return True

    def finish_cleanup(self):
        while True:
            try:
                if self.step_cleanup():
                    return
                time.sleep(.05)
            except BaseException as error:
                self.failure(error, "cleanup_interrupt")


def wrapper(payload):
    spec = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
    assert_source(spec["source_pin"])
    from contextlib import redirect_stderr
    from sentinel.adaptive import wrapper_host, native_launcher
    from sentinel.adaptive.contracts import Priority, ResourceDemand, Role
    from sentinel.adaptive.launcher import ManagedLauncher
    directory, _ = authorize(spec["directory"], spec["token"])
    raw = {"started_tick": tick(), "launches": 0, "native_calls": [], "infrastructure_failure": None}
    custody = _WrapperCustody(directory, raw)
    def create(job, application, command_line, **kwargs):
        assert_source(spec["source_pin"])
        write(directory / "expected-job.json", {"name": job.name, "nonce": job.nonce,
                                               "logon_id": job.logon_sid})
        raw["launches"] += 1
        raw["create_started_tick"] = tick()
        def observe(result):
            raw["create_returned_tick"] = tick()
            raw["root_identity"] = result.identity()
            provenance = getattr(result, "launch_provenance", None)
            if provenance is not None:
                raw["launch_provenance"] = provenance.to_dict()
            raw["native_calls"].append("CreateProcessW:JOB_LIST:HANDLE_LIST")
            write(directory / "wrapper-launch.json", raw)
        return custody.observe_launch(native_launcher, job, application, command_line, observe, **kwargs)
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
    result = 125
    try:
        events = (directory / "wrapper-events.jsonl").open("a", encoding="utf-8")
        custody.defer_cleanup("events", events.close)
        # This changes only Python's logging stream. The production host reads
        # fd 2 via msvcrt, so actual workload stderr keeps the inherited handle.
        with redirect_stderr(events):
            try:
                assert_source(spec["source_pin"])
                guardian = spec["guardian"]
                host = custody.construct(ObservedHost, data_dir=spec["data_dir"],
                    command=spec["command"], cwd=str(directory),
                    repo_identifier="sentinel-native-s2", role=Role.BACKGROUND, priority=Priority.P2,
                    requested=ResourceDemand(1.0, 256 * 1024**2, 256 * 1024**2, 0),
                    guardian_epoch=guardian["epoch"], guardian_pid=guardian["pid"],
                    guardian_created_filetime_100ns=int(guardian["birth"]),
                    endpoint_instance_id=guardian["endpoint_instance_id"], launcher_factory=factory,
                    max_wait_sec=90)
                with wrapper_host._owned_interrupts(host):
                    try:
                        if spec.get("probe_null_stdio"):
                            # Test this fixture's own fd 0. Register every
                            # restoration before changing it; never alter fd 2.
                            import ctypes
                            import msvcrt
                            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                            kernel.GetStdHandle.restype = ctypes.c_void_p
                            kernel.GetStdHandle.argtypes = (ctypes.c_ulong,)
                            kernel.SetStdHandle.restype = ctypes.c_int
                            kernel.SetStdHandle.argtypes = (ctypes.c_ulong, ctypes.c_void_p)
                            selector = ctypes.c_ulong(-10 & 0xffffffff)
                            previous_stdin = kernel.GetStdHandle(selector)
                            original_stdin = msvcrt.get_osfhandle(0)
                            if (type(original_stdin) is not int or original_stdin <= 0 or
                                    previous_stdin != original_stdin):
                                raise RuntimeError("s2_stdin_selector_not_original_descriptor")
                            saved_stdin_fd = os.dup(0)
                            custody.defer_cleanup("stdin_fd_restore", lambda: os.dup2(saved_stdin_fd, 0))
                            custody.defer_cleanup("stdin_selector_restore",
                                _WrapperStdinSelector(kernel, msvcrt, selector))
                            custody.defer_cleanup("stdin_saved_fd", lambda: os.close(saved_stdin_fd))
                            if not kernel.SetStdHandle(selector, None):
                                raise ctypes.WinError(ctypes.get_last_error())
                            os.close(0)
                        assert_source(spec["source_pin"])
                        result = host.run()
                    except BaseException as error:
                        custody.failure(error)
                    finally:
                        custody.finish_host()
            except BaseException as error:
                custody.failure(error)
            finally:
                custody.finish_host()
    except BaseException as error:
        custody.failure(error)
    finally:
        # Source drift, a failed logger/context exit, or another interrupt must
        # never prevent original cleanup. No assert_source belongs in recovery.
        custody.finish_host()
        custody.finish_cleanup()
    if raw["infrastructure_failure"] is not None:
        result = 125
    try:
        raw.update(ended_tick=tick(), host_exit_code=result, local_cleanup_closed=custody.host_settled)
        write(directory / "wrapper-result.json", raw)
    except BaseException as error:
        custody.failure(error, "result_publication")
        result = 125
    return result


def _original_shell_exit_code(handle):
    import _winapi
    status = _winapi.WaitForSingleObject(handle, 0)
    if status == _winapi.WAIT_TIMEOUT:
        return None
    if status != _winapi.WAIT_OBJECT_0:
        raise RuntimeError("s2_original_shell_wait_unverified")
    code = _winapi.GetExitCodeProcess(handle)
    if type(code) is not int or not 0 <= code <= 0xffffffff:
        raise RuntimeError("s2_original_shell_exit_unverified")
    return code


def _owned_console_ancestry(native, held, fixture_identity):
    process = _open_observer(native, held, fixture_identity["pid"], fixture_identity["created_filetime_100ns"])
    identities, child_birth = {}, None
    for depth in range(12):
        identity = process.identity()
        if process.wait(0) or (child_birth is not None and int(identity["created_filetime_100ns"]) > child_birth):
            raise RuntimeError("s2_console_ancestor_unverified")
        identities[identity["pid"]] = identity
        if identity["pid"] == os.getpid():
            return identities
        if depth == 11:
            raise RuntimeError("s2_console_ancestry_not_owned")
        child_birth = int(identity["created_filetime_100ns"])
        process = _open_observer(native, held, process.parent_pid())
    raise RuntimeError("s2_console_ancestry_not_owned")


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
        self._original_shell = self._original_shell_handle = None
        self._shell_binding_entered = self._shell_bound = False
        self._original_shell_streams = None
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
        if isinstance(error, S2ObserverOpenPending):
            self.quarantined = True

    def bind_shell(self, shell):
        if self._shell_binding_entered or self._original_shell is not None:
            raise RuntimeError("s2_console_shell_already_bound")
        self._shell_binding_entered = True
        self.shell = self._original_shell = shell
        # The returned Popen is retained before accessing its native handle.
        self._original_shell_handle = shell._handle
        if self._original_shell_handle is None:
            raise RuntimeError("s2_shell_creation_handle_missing")
        self._original_shell_streams = (shell.stdin, shell.stdout, shell.stderr)
        self._shell_bound = True

    def _shell_original(self):
        if self._original_shell is None:
            return self.shell is None and not self._shell_binding_entered
        return (self._shell_bound and self.shell is self._original_shell and
                self.shell._handle is self._original_shell_handle and
                all(actual is original for actual, original in zip(
                    (self.shell.stdin, self.shell.stdout, self.shell.stderr), self._original_shell_streams)))

    def _unknown(self, category, error):
        self.remember(category, error)
        self.quarantined = True
        return False

    def step(self):
        if self.quarantined:
            return False
        try:
            if not self._shell_original():
                return self._unknown("shell_binding", RuntimeError("s2_original_shell_binding_changed"))
        except BaseException as error:
            return self._unknown("shell_binding", error)
        if self.settled:
            return True
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
            code = None if self.shell is None else _original_shell_exit_code(self._original_shell_handle)
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
        try:
            if not self._shell_original():
                return self._unknown("shell_binding", RuntimeError("s2_original_shell_binding_changed"))
        except BaseException as error:
            return self._unknown("shell_binding", error)
        # Shell exit alone is insufficient: surviving descendants retain the
        # owned console. Close originals only after both positive observations.
        owners = [*self.held, *self.files]
        if self.shell is not None:
            self.shell.returncode = code
            owners.extend(stream for stream in self._original_shell_streams
                          if stream is not None)
            owners.append(self._original_shell_handle)
        for owner in owners:
            if id(owner) in self._closed:
                continue
            # Publish the attempted owner before the native/file close. A
            # failed call stays quarantined and is never retried blindly.
            self._closing = owner
            try:
                (owner.Close if owner is self._original_shell_handle else owner.close)()
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
    assert_source(spec["source_pin"])
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
        assert_source(spec["source_pin"])
        custody.creation_started = True
        shell = subprocess.Popen(spec["shell_args"], cwd=directory, **streams)
        custody.bind_shell(shell)
        if send_signal:
            shell_handle = _open_observer(native, held, shell.pid)
            fixture = wait_json(directory / "signal-ready.json", 30)
            if fixture["stdio_isatty"] != [profile == "console"] * 3:
                raise RuntimeError("s2_console_stdio_not_preserved")
            # Only this fixture's exact native ancestry can authorize a signal.
            identities = _owned_console_ancestry(native, held, fixture["identity"])
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
        if shell is not None and custody._original_shell is None:
            # No late handle adoption: retain the returned Popen, but preserve
            # the missing immediate binding as an unknown acquisition outcome.
            custody.shell = custody._original_shell = shell
            custody._unknown("creation_binding", RuntimeError("s2_shell_binding_ack_unknown"))
        def publish():
            write(directory / "console-result.json", raw)
            (directory / "driver-stdout.bin").write_bytes(output or b"")
            (directory / "driver-stderr.bin").write_bytes(errors or b"")
        custody.finish(raw, publish)
    return 0 if not raw.get("error") and raw.get("cleanup_verified") and (not send_signal or raw.get("ctrl_c_received")) else 125


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-pin", required=True)
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
    assert_source(_decode_pin(args.source_pin))
    try:
        return wrapper(args.payload) if args.action == "wrapper" else console_driver(args.payload) if args.action == "console" else workload(args)
    except S2ObserverOpenPending as error:
        _retain_observer_open_failure(error)
        raise RuntimeError("s2_observer_custody_returned_without_completion") from error


if __name__ == "__main__":
    _module = _load_bootstrap()
    _SOURCE_BOOTSTRAP = _module.bootstrap()
    if sys.argv[1:] == ["--check-source"]:
        print(json.dumps(dict(status="source_verified", promotion=False,
                              source_pin=_SOURCE_BOOTSTRAP.source_pin()), sort_keys=True))
        raise SystemExit(0)
    raise SystemExit(main())
