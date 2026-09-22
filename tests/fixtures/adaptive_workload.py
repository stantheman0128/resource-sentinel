"""Fixed, non-private commands for external P6 measurements.

This is a workload, never an admission provider. The orchestrator must acquire
the real host's continuous demand floor before invoking it. Work units, memory,
disk input, child count and cooperative deadline are bounded. All children are
our own and are waited for; no kill, Job mutation, network or user files.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
import zipfile


SCENARIOS = ("cpu_bound_build", "io_bound_install", "memory_heavy_test", "no_pressure_idle")
MAX_TASKS = 4
MAX_UNITS = 10000
MAX_MEMORY_MIB = 128
MAX_SECONDS = 120
DATASET_VERSION = "sentinel-p6-public-fixture-v1"
_INTERRUPTED = False


def _request_stop(signum, frame):
    global _INTERRUPTED
    _INTERRUPTED = True


def dataset_bytes():
    return hashlib.sha256(DATASET_VERSION.encode("ascii")).digest() * 32768


def dataset_sha256():
    return hashlib.sha256(dataset_bytes()).hexdigest()


def write_json(path, record):
    """Exclusive create: a second attempt cannot replace a run's evidence."""
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True, allow_nan=False)


def validate_options(options):
    if options.scenario not in SCENARIOS:
        raise ValueError("unsupported_fixture_scenario")
    if not 1 <= options.tasks <= MAX_TASKS or not 1 <= options.units <= MAX_UNITS:
        raise ValueError("fixture_work_bound_invalid")
    if not 1 <= options.memory_mib <= MAX_MEMORY_MIB:
        raise ValueError("fixture_memory_bound_invalid")
    if not math.isfinite(options.seconds) or not 1 <= options.seconds <= MAX_SECONDS:
        raise ValueError("fixture_deadline_invalid")
    if options.deadline_ns is not None and (options.deadline_ns <= time.monotonic_ns() or
            options.deadline_ns > time.monotonic_ns() + int(MAX_SECONDS * 1e9)):
        raise ValueError("fixture_parent_deadline_invalid")
    directory = options.directory
    if not directory.is_absolute() or not directory.is_dir() or directory.is_symlink():
        raise ValueError("fixture_directory_invalid")
    if options.leaf is not None and not 0 <= options.leaf < options.tasks:
        raise ValueError("fixture_leaf_invalid")


def own_identity():
    if os.name != "nt":
        return {"pid": os.getpid(), "created_filetime_100ns": None}
    # A leaf records its original native object. The observer verifies this
    # creation time while opening a query handle; a PID alone is insufficient.
    from ctypes import byref, c_void_p, c_uint32, Structure, WinDLL, sizeof
    class FileTime(Structure):
        _fields_ = [("low", c_uint32), ("high", c_uint32)]
    kernel = WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes, kernel.GetCurrentProcess.restype = [], c_void_p
    kernel.GetProcessTimes.argtypes = [c_void_p] + [__import__("ctypes").POINTER(FileTime)] * 4
    kernel.GetProcessTimes.restype = c_uint32
    created, exited, system, user = (FileTime() for _ in range(4))
    if sizeof(FileTime) != 8 or not kernel.GetProcessTimes(kernel.GetCurrentProcess(),
            byref(created), byref(exited), byref(system), byref(user)):
        raise RuntimeError("fixture_identity_query_failed")
    return {"pid": os.getpid(), "created_filetime_100ns": str((created.high << 32) | created.low)}


def wheel_bytes(directory):
    """Build one deterministic public wheel; pip later installs it offline."""
    target = directory / "sentinel_p6_fixture-1.0-py3-none-any.whl"
    entries = {
        "sentinel_p6_fixture/__init__.py": b"VALUE = 'sentinel-p6-public-fixture-v1'\n",
        "sentinel_p6_fixture/data.bin": dataset_bytes() * 8,
        "sentinel_p6_fixture-1.0.dist-info/METADATA": b"Metadata-Version: 2.1\nName: sentinel-p6-fixture\nVersion: 1.0\n",
        "sentinel_p6_fixture-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: sentinel-p6\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    rows = []
    for name, payload in sorted(entries.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        rows.append(f"{name},sha256={digest},{len(payload)}\n")
    record = "sentinel_p6_fixture-1.0.dist-info/RECORD"
    entries[record] = ("".join(rows) + record + ",,\n").encode("utf-8")
    with zipfile.ZipFile(target, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            archive.writestr(info, payload)
    return target


def _leaf(options, deadline):
    started = time.monotonic_ns()
    cpu = time.process_time_ns()
    identity = own_identity()
    write_json(options.directory / f"ready-{options.leaf}.json", {
        **identity, "schema_version": 1, "started_ns": started,
        "deadline_ns": deadline, "dataset_sha256": dataset_sha256(),
        "scenario": options.scenario, "leaf": options.leaf,
    })
    stop = options.directory / "stop-workload"
    completed = 0
    failure = None
    def running():
        return not _INTERRUPTED and not stop.exists() and time.monotonic_ns() < deadline
    try:
        if options.scenario == "cpu_bound_build":
            data = dataset_bytes()
            expected = hashlib.sha256(data).digest()
            # Real fixed unittest assertions, without claiming this is a build
            # benchmark for a third-party repository.
            case = unittest.TestCase()
            while completed < options.units and running():
                case.assertEqual(hashlib.sha256(data).digest(), expected)
                completed += 1
        elif options.scenario == "memory_heavy_test":
            memory = bytearray(options.memory_mib * (1 << 20))
            case = unittest.TestCase()
            while completed < options.units and running():
                value = completed % 251
                for index in range(0, len(memory), 4096):
                    memory[index] = value
                case.assertEqual(sum(memory[::4096]), value * len(memory[::4096]))
                completed += 1
        elif options.scenario == "no_pressure_idle":
            while completed < options.units and running():
                time.sleep(min(.01, max(0, (deadline - time.monotonic_ns()) / 1e9)))
                completed += 1
        else:
            wheel = options.directory / "sentinel_p6_fixture-1.0-py3-none-any.whl"
            if not wheel.is_file():
                raise RuntimeError("fixture_wheel_missing")
            # One bounded offline installation per unit. No network, package
            # scripts, user site, bytecode compilation or executable entrypoint.
            # pip has no safe cooperative cancellation API: retain and wait the
            # original child if it outlasts the observer deadline. Never kill.
            while completed < options.units and running():
                target = options.directory / f"install-{options.leaf}-{completed}"
                with (options.directory / f"pip-{options.leaf}-{completed}.log").open("xb") as log:
                    child = subprocess.Popen([sys.executable, "-m", "pip", "install", "--no-index",
                        "--no-deps", "--no-compile", "--disable-pip-version-check", "--no-warn-script-location",
                        "--target", str(target), str(wheel)], stdout=log, stderr=log,
                        env={**os.environ, "PIP_CONFIG_FILE": os.devnull, "PYTHONNOUSERSITE": "1"})
                    result = child.wait()
                if result != 0:
                    raise RuntimeError("fixture_offline_install_failed")
                installed = target / "sentinel_p6_fixture" / "data.bin"
                if installed.stat().st_size != 8 << 20:
                    raise RuntimeError("fixture_offline_install_incomplete")
                completed += 1
        if completed != options.units:
            failure = "fixture_stopped" if stop.exists() else "fixture_deadline_exceeded"
    except Exception as error:
        failure = type(error).__name__
    record = {"schema_version": 1, **identity, "leaf": options.leaf,
        "scenario": options.scenario, "started_ns": started, "ended_ns": time.monotonic_ns(),
        "cpu_time_ns": time.process_time_ns() - cpu, "completed_units": completed,
        "requested_units": options.units, "status": "complete" if failure is None else "failed",
        "reason": failure, "all_children_exited": True}
    write_json(options.directory / f"result-{options.leaf}.json", record)
    return 0 if failure is None else 3


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=SCENARIOS)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--tasks", type=int, default=1)
    parser.add_argument("--units", type=int, default=1000)
    parser.add_argument("--memory-mib", type=int, default=128)
    parser.add_argument("--seconds", type=float, default=120)
    parser.add_argument("--leaf", type=int)
    parser.add_argument("--deadline-ns", type=int)
    options = parser.parse_args(argv)
    # A console interrupt requests cooperative exit. It cannot unwind the
    # Python frame which owns an original child handle during wait().
    signal.signal(signal.SIGINT, _request_stop)
    try:
        validate_options(options)
        if options.scenario == "io_bound_install" and options.units > 8:
            raise ValueError("fixture_disk_bound_invalid")
    except ValueError as error:
        parser.error(str(error))
    deadline = min(time.monotonic_ns() + int(options.seconds * 1e9),
                   options.deadline_ns or (1 << 63))
    if options.leaf is not None:
        return _leaf(options, deadline)
    if options.scenario == "io_bound_install":
        wheel_bytes(options.directory)
    children = []
    interrupted = False
    try:
        for index in range(options.tasks):
            args = [sys.executable, str(Path(__file__).resolve()), "--scenario", options.scenario,
                    "--directory", str(options.directory), "--tasks", str(options.tasks),
                    "--units", str(options.units), "--memory-mib", str(options.memory_mib),
                    "--seconds", str(options.seconds), "--leaf", str(index), "--deadline-ns", str(deadline)]
            children.append(subprocess.Popen(args))
        outcomes = []
        for child in children:
            outcomes.append(child.wait())
    except BaseException:
        interrupted = True
        (options.directory / "stop-workload").touch(exist_ok=True)
    finally:
        # Original child handles remain held until every child really exits.
        for child in children:
            while child.poll() is None:
                try:
                    child.wait(timeout=.25)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    continue
    return 3 if interrupted else (0 if all(value == 0 for value in outcomes) else 3)


if __name__ == "__main__":
    raise SystemExit(main())
