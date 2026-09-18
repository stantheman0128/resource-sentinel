"""Owned, bounded S2 fixtures. Never invoke against a production data directory.

Every process verifies a per-case authorization nonce and shares an absolute
deadline of at most 120 seconds. The fixture exits itself at that deadline;
the scheduler never kills a workload to make a recovery assertion pass.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def write_json(path: Path, value: object) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    os.replace(temporary, path)


def authorized(directory: Path, token: str) -> dict:
    directory = directory.resolve(strict=True)
    if ".resource-sentinel" in (part.casefold() for part in directory.parts):
        raise ValueError("production_directory_forbidden")
    record = json.loads((directory / "fixture-authorization.json").read_text("utf-8"))
    remaining = float(record["deadline_unix"]) - time.time()
    if record.get("token") != token or not 0 < remaining <= 120:
        raise ValueError("fixture_authorization_invalid")
    timer = threading.Timer(remaining, lambda: os._exit(124))
    timer.daemon = True
    timer.start()
    return record


def identity_record(directory: Path, label: str, api_root: str) -> dict:
    # The first substantive fixture action is an exact birth/membership query.
    # This code does not create a Job, mutate CPU control, or call host preflight.
    sys.path.insert(0, api_root)
    from tests.windows import adaptive_win32 as native

    current = native.ProcessHandle.open_current()
    try:
        record = {
            "identity": current.identity(),
            "parent_pid": current.parent_pid(),
            "label": label,
            "observed_unix": time.time(),
            "job_membership": None,
            "stdio_isatty": [sys.stdin.isatty(), sys.stdout.isatty(), sys.stderr.isatty()],
        }
        parent = native.ProcessHandle.open(record["parent_pid"])
        try:
            record["parent_identity"] = parent.identity()
        finally:
            parent.close()
        expected = directory / "expected-job.json"
        if expected.exists():
            job_spec = json.loads(expected.read_text("utf-8"))
            job = native.OwnedJob.open(job_spec["name"], job_spec["nonce"])
            try:
                record["job_membership"] = current.is_in_job(job)
            finally:
                job.close()
            if record["job_membership"] is not True:
                raise RuntimeError("fixture_started_outside_expected_job")
        write_json(directory / (label + ".ready.json"), record)
        return record
    finally:
        current.close()


def emit_streams(size: int) -> None:
    # Concurrent output exceeds ordinary pipe buffers without unbounded memory.
    def emit(stream, char: bytes) -> None:
        remaining = size
        while remaining:
            block = char * min(4096, remaining)
            stream.write(block)
            stream.flush()
            remaining -= len(block)

    writers = [
        threading.Thread(target=emit, args=(sys.stdout.buffer, b"O")),
        threading.Thread(target=emit, args=(sys.stderr.buffer, b"E")),
    ]
    for writer in writers:
        writer.start()
    for writer in writers:
        writer.join()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--token", required=True)
    parser.add_argument("--api-root", required=True)
    parser.add_argument("--mode", choices=("io", "quiet", "leaf", "tree", "collector", "signal"), required=True)
    parser.add_argument("--label", default="root")
    parser.add_argument("--exit-code", type=int, default=0)
    parser.add_argument("--seconds", type=float, default=3.0)
    parser.add_argument("--literal", action="append", default=[])
    parser.add_argument("--read-stdin", action="store_true")
    parser.add_argument("--large-bytes", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.seconds <= 90 or not 0 <= args.large_bytes <= 1048576:
        parser.error("bounded_fixture_limits_exceeded")
    authorized(args.directory, args.token)
    record = identity_record(args.directory, args.label, args.api_root)

    if args.mode in ("io", "quiet"):
        data = sys.stdin.buffer.read(1048577) if args.read_stdin else b""
        if len(data) > 1048576:
            raise ValueError("fixture_stdin_too_large")
        record.update(literals=args.literal, stdin_hex=data.hex())
        if args.mode == "io":
            if args.large_bytes:
                emit_streams(args.large_bytes)
            else:
                sys.stdout.buffer.write("stdout: 測試 Ω\n".encode("utf-8") + data)
                sys.stderr.buffer.write("stderr: 測試 Ω\n".encode("utf-8"))
                sys.stdout.buffer.flush()
                sys.stderr.buffer.flush()
    elif args.mode == "signal":
        received = threading.Event()
        signal.signal(signal.SIGINT, lambda *_: received.set())
        write_json(args.directory / "signal-handler-ready.json", record)
        until = time.monotonic() + min(args.seconds, 90)
        while not received.is_set() and time.monotonic() < until and not (args.directory / "stop").exists():
            received.wait(0.05)
        if not received.is_set():
            record["ctrl_c_received"] = False
            write_json(args.directory / (args.label + ".done.json"), record)
            return 124
        record["ctrl_c_received"] = True
    elif args.mode in ("tree", "collector"):
        command = [
            sys.executable, str(Path(__file__).resolve()), "--mode", "leaf",
            "--directory", str(args.directory), "--token", args.token,
            "--api-root", args.api_root, "--label", "child", "--seconds", str(args.seconds),
        ]
        # A new process group deliberately does not escape parentage or Job
        # inheritance. This matches the existing adapter's relevant flag.
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if args.mode == "collector" else 0
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=flags)
        ready = args.directory / "child.ready.json"
        until = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < until:
            time.sleep(0.02)
        if not ready.exists():
            raise RuntimeError("fixture_child_readiness_timeout")
        record["child_identity"] = json.loads(ready.read_text("utf-8"))["identity"]
        record["popen_child_pid"] = child.pid
        write_json(args.directory / (args.label + ".children.json"), record)
        if args.mode == "collector":
            deadline = time.monotonic() + args.seconds
            while time.monotonic() < deadline and not (args.directory / "stop").exists():
                time.sleep(0.05)
    else:
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline and not (args.directory / "stop").exists():
            time.sleep(0.05)

    record["completed_unix"] = time.time()
    write_json(args.directory / (args.label + ".done.json"), record)
    return args.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
