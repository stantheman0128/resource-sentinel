"""Real Windows query IPC in isolated ledgers; no Job or control capability.

Only the outer test command needs normal host admission. Fixture resource frames
admit metadata, never workloads through an alternate capacity ledger. The child
mode is a bounded voluntary query server, with no kill or crash cleanup path.
"""
from contextlib import closing
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.admission import ManagedAdmission
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.ipc import IpcError, LifecycleQueryService, ManagedExecutionClient
from sentinel.adaptive import pipe_windows
from sentinel.adaptive.pipe_windows import (
    NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeError,
    NativePipeListener, NativePipeRegistry,
)
from sentinel.coordinator import Coordinator
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, NOW, status


def _ledger_digest(path):
    # Assertions expose only a digest, never the private credential columns.
    with closing(sqlite3.connect(path)) as conn:
        return hashlib.sha256("\n".join(conn.iterdump()).encode("utf-8")).hexdigest()


def _finish_resources(registry, resources, timeout=5.0):
    """Cancellation is only a request; observe original completion before free."""
    until = time.monotonic() + timeout
    while True:
        for resource in resources:
            try:
                resource.close()
            except NativePipeError:
                # A pending OVERLAPPED must remain owned until reap confirms it.
                pass
        current = registry.reap(NativeDeadline.after_ms(100))
        if current.resources == current.pending == current.quarantined == 0:
            return current
        if time.monotonic() >= until:
            raise AssertionError(f"native pipe cleanup unverified: {current}")
        time.sleep(.01)


def _child_server(directory, instance_id):
    """Small test-only server; no inherited credential or process control."""
    directory = Path(directory)
    registry = NativePipeRegistry()
    listener = None
    result = {"ok": False}
    try:
        with VerifiedProcess.current() as current:
            endpoint = NativePipeEndpoint(current.identity.logon_id, instance_id, current.identity)
            listener = NativePipeListener(endpoint, registry=registry)
            bootstrap = directory / "ipc-child-bootstrap.json"
            temporary = bootstrap.with_suffix(".tmp")
            temporary.write_text(json.dumps({"identity": current.identity.to_dict(),
                "instance_id": instance_id}), encoding="utf-8")
            temporary.replace(bootstrap)
            service = LifecycleQueryService(directory / "sentinel.db", endpoint)
            responses = [service.serve_once(listener, timeout_ms=5000) for _ in range(2)]
            result = {"ok": True, "operations": [r["operation"] for r in responses],
                      "receipts": all(r["receipt_verified"] for r in responses)}
    except BaseException as error:
        # Test artifacts omit exception messages and all wire/key material.
        result = {"ok": False, "error_type": type(error).__name__,
                  "reason": getattr(error, "reason", None)}
    finally:
        try:
            final = _finish_resources(registry, [] if listener is None else [listener])
            result["remaining_resources"] = final.resources
        except BaseException as error:
            result["ok"] = False
            result["cleanup_error_type"] = type(error).__name__
        (directory / "ipc-child-result.json").write_text(json.dumps(result), encoding="utf-8")
    return 0 if result["ok"] else 1


@unittest.skipUnless(os.name == "nt", "real Named Pipe IPC requires Windows")
class NativeLifecycleIpcTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        self.context = ManagedAdmission.current(**PAYLOAD)
        self.addCleanup(self.context.close)
        self.snapshot = self.context.snapshot()
        self.admitted = self.coordinator.admit_managed(self.context, status(now=NOW),
                                                       config=CONFIG, now=NOW)
        self.assertTrue(self.admitted["allowed"], self.admitted)
        self.registry = NativePipeRegistry()
        registry_override = patch.object(pipe_windows, "_GLOBAL_REGISTRY", self.registry)
        registry_override.start()
        self.addCleanup(registry_override.stop)
        self.resources = []
        self.addCleanup(_finish_resources, self.registry, self.resources)
        self.endpoint = NativePipeEndpoint(self.snapshot.logon_id, str(uuid4()),
                                            self.snapshot.wrapper_identity)

    def listener(self, endpoint=None):
        listener = NativePipeListener(endpoint or self.endpoint, registry=self.registry)
        self.resources.append(listener)
        return listener

    def start(self, operation):
        result, done = {}, threading.Event()

        def run():
            try:
                result["value"] = operation()
            except BaseException as error:
                result["error"] = error
            finally:
                done.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(self.join, thread, done)
        return thread, done, result

    @staticmethod
    def join(thread, done):
        thread.join(timeout=7)
        if thread.is_alive() or not done.is_set():
            raise AssertionError("bounded native server thread did not finish")

    def request(self, listener, operation="QueryExecution"):
        service = LifecycleQueryService(self.coordinator.db_path, listener.endpoint)
        thread, done, served = self.start(lambda: service.serve_once(listener, timeout_ms=5000))
        client = ManagedExecutionClient(self.context, listener.endpoint)
        query = (client.query_execution if operation == "QueryExecution" else client.get_readiness)
        result = query(timeout_ms=5000)
        self.join(thread, done)
        if "error" in served:
            raise served["error"]
        self.assertTrue(served["value"]["receipt_verified"])
        self.assertEqual(served["value"]["operation"], operation)
        self.assertFalse(served["value"]["control_writes"])
        return result

    def test_query_and_readiness_are_native_readonly_and_preserve_unused_cancellation(self):
        listener = self.listener()
        before = _ledger_digest(self.coordinator.db_path)
        query = self.request(listener)
        readiness = self.request(listener, "GetReadiness")
        self.assertEqual(query["executions"][0]["execution_id"], self.snapshot.execution_id)
        self.assertEqual(query["executions"][0]["state"], "RESERVED")
        self.assertEqual(query["executions"][0]["wrapper"], {
            "pid": os.getpid(), "created_filetime_100ns": str(self.snapshot.wrapper_identity.created_filetime_100ns)})
        self.assertEqual(readiness["execution_id"], self.snapshot.execution_id)
        for value in (query, readiness):
            self.assertEqual(value["implementation_mode"], "admission-only")
            self.assertEqual(value["native_readiness"], "unverified")
            self.assertEqual(value["os_limit_state"], "unverified")
            self.assertEqual(value["recorded_mode"], "off")
            self.assertFalse(value["control_writes"])
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)
        self.assertFalse(self.context._claim_exported)
        cancelled = self.context.cancel_reserved(self.coordinator.db_path,
            reservation_id=self.admitted["reservation_id"], expected_revision=0, now=NOW + 1)
        self.assertTrue(cancelled["cancelled"])
        terminal_before = _ledger_digest(self.coordinator.db_path)
        self.assertEqual(self.request(listener)["executions"][0]["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(_ledger_digest(self.coordinator.db_path), terminal_before)
        listener.close()
        self.assertEqual(self.registry.status().resources, 0)
        self.assertIsNone(listener._owner._handle)

    def test_wrong_server_pin_is_rejected_before_frame_or_credential(self):
        listener = self.listener()
        original = self.snapshot.wrapper_identity
        other_logon = "S-1-5-5-0-0" if original.logon_id != "S-1-5-5-0-0" else "S-1-5-5-0-1"
        bad = (replace(original, pid=0xFFFFFFFC),
               replace(original, created_filetime_100ns=original.created_filetime_100ns + 1),
               replace(original, logon_id=other_logon))
        before = _ledger_digest(self.coordinator.db_path)
        for expected in bad:
            with self.subTest(changed_pid=expected.pid != original.pid,
                              changed_logon=expected.logon_id != original.logon_id):
                endpoint = NativePipeEndpoint(expected.logon_id, self.endpoint.instance_id, expected)
                with patch.object(self.context, "_ipc_mac", side_effect=AssertionError("credential used before server pin")), \
                     patch("sentinel.adaptive.ipc.write_frame", side_effect=AssertionError("frame sent before server pin")):
                    with self.assertRaises((NativePipeError, IpcError)):
                        ManagedExecutionClient(self.context, endpoint).query_execution(timeout_ms=1000)
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)
        self.assertEqual(self.request(listener)["executions"][0]["state"], "RESERVED")

    def test_real_pipe_peer_rejects_wrong_pid_birth_and_logon(self):
        listener = self.listener()
        original = self.snapshot.wrapper_identity
        other_logon = "S-1-5-5-0-0" if original.logon_id != "S-1-5-5-0-0" else "S-1-5-5-0-1"
        wrong = (replace(original, pid=0xFFFFFFFC),
                 replace(original, created_filetime_100ns=original.created_filetime_100ns + 1),
                 replace(original, logon_id=other_logon))
        before = _ledger_digest(self.coordinator.db_path)
        for expected in wrong:
            def serve():
                deadline = NativeDeadline.after_ms(5000)
                with listener.accept(deadline) as connection:
                    self.assertEqual(connection.peer_pid(), os.getpid())
                    with self.assertRaises(NativePipeError):
                        with connection.verified_peer(expected):
                            self.fail("forged peer identity accepted")
                    with connection.verified_peer(original) as retained:
                        self.assertEqual(retained.identity, original)
                        self.assertIs(retained.observe().status, IdentityStatus.ALIVE)
                    connection.write_all(b"verified", deadline)
                    self.assertEqual(connection.read_exact(1, deadline), b"!")
            thread, done, served = self.start(serve)
            deadline = NativeDeadline.after_ms(5000)
            with NativePipeConnection.connect(self.endpoint, deadline, registry=self.registry) as connection:
                self.assertEqual(connection.read_exact(8, deadline), b"verified")
                connection.write_all(b"!", deadline)
            self.join(thread, done)
            if "error" in served:
                raise served["error"]
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)

    def test_idle_accept_timeout_reaps_original_io_before_endpoint_reuse(self):
        listener = self.listener()
        before = _ledger_digest(self.coordinator.db_path)
        with self.assertRaises(NativePipeError) as raised:
            listener.accept(NativeDeadline.after_ms(200))
        self.assertEqual(raised.exception.reason, "pipe_timeout")
        final = _finish_resources(self.registry, [listener])
        self.assertEqual((final.resources, final.pending, final.quarantined), (0, 0, 0))
        self.assertIsNone(listener._owner._handle)
        self.assertIsNone(listener._owner._operation)
        # FILE_FLAG_FIRST_PIPE_INSTANCE now succeeds for the very same name.
        replacement = self.listener()
        self.assertEqual(self.request(replacement)["executions"][0]["state"], "RESERVED")
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)

    def test_partial_prefix_and_body_timeouts_keep_ledger_unchanged_and_reap(self):
        before = _ledger_digest(self.coordinator.db_path)
        for payload in (b"\x20\x00", struct.pack("<I", 32) + b"{"):
            with self.subTest(partial_prefix=len(payload) == 2):
                listener = self.listener(replace(self.endpoint, instance_id=str(uuid4())))
                service = LifecycleQueryService(self.coordinator.db_path, listener.endpoint)
                thread, done, served = self.start(lambda: service.serve_once(listener, timeout_ms=1000))
                connection = NativePipeConnection.connect(listener.endpoint,
                    NativeDeadline.after_ms(2000), registry=self.registry)
                self.resources.append(connection)
                connection.write_all(payload, NativeDeadline.after_ms(2000))
                self.join(thread, done)
                self.assertIn("error", served)
                self.assertIsInstance(served["error"], (NativePipeError, IpcError))
                self.assertIn(str(served["error"]), {"pipe_timeout", "ipc_deadline_exceeded"})
                _finish_resources(self.registry, [connection, listener])
                self.assertIsNone(listener._owner._operation)
                self.assertIsNone(listener._owner._handle)
                self.assertIsNone(connection._owner._handle)
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)
        self.assertFalse(self.context._claim_exported)

    def test_separate_voluntary_server_verifies_real_cross_process_peers(self):
        instance = str(uuid4())
        before = _ledger_digest(self.coordinator.db_path)
        child = subprocess.Popen([sys.executable, "-m", "tests.test_adaptive_native_ipc",
            "--pipe-child-server", str(self.directory), instance],
            cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)

        def wait_child():
            # The child has at most two finite requests and bounded cleanup.
            # Timeout reports an unresolved fixture; never kill a process tree.
            child.wait(timeout=18)
        self.addCleanup(wait_child)
        bootstrap = self.directory / "ipc-child-bootstrap.json"
        until = time.monotonic() + 10
        while not bootstrap.is_file() and child.poll() is None and time.monotonic() < until:
            time.sleep(.01)
        if not bootstrap.is_file():
            outcome = self.directory / "ipc-child-result.json"
            detail = json.loads(outcome.read_text(encoding="utf-8")) if outcome.is_file() else {"returncode": child.poll()}
            self.fail(f"bounded child bootstrap unavailable: {detail}")
        info = json.loads(bootstrap.read_text(encoding="utf-8"))
        expected = ProcessIdentity.from_dict(info["identity"])
        self.assertEqual(expected.pid, child.pid)
        self.assertNotEqual(expected.pid, os.getpid())
        self.assertEqual(expected.logon_id, self.snapshot.logon_id)
        self.assertEqual(info["instance_id"], instance)
        endpoint = NativePipeEndpoint(expected.logon_id, instance, expected)
        with VerifiedProcess.open(expected) as retained:
            self.assertIs(retained.observe().status, IdentityStatus.ALIVE)
            client = ManagedExecutionClient(self.context, endpoint)
            query = client.query_execution(timeout_ms=5000)
            readiness = client.get_readiness(timeout_ms=5000)
            self.assertEqual(query["executions"][0]["wrapper"]["pid"], os.getpid())
            self.assertEqual(readiness["execution_id"], self.snapshot.execution_id)
            self.assertEqual(readiness["native_readiness"], "unverified")
            self.assertEqual(child.wait(timeout=10), 0)
            self.assertIs(retained.observe().status, IdentityStatus.DEAD)
        result = json.loads((self.directory / "ipc-child-result.json").read_text(encoding="utf-8"))
        self.assertTrue(result["ok"], result)
        self.assertTrue(result["receipts"])
        self.assertEqual(result["operations"], ["QueryExecution", "GetReadiness"])
        self.assertEqual(result["remaining_resources"], 0)
        self.assertEqual(_ledger_digest(self.coordinator.db_path), before)
        self.assertEqual(self.registry.status().resources, 0)
        self.assertFalse(self.context._claim_exported)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--pipe-child-server":
        raise SystemExit(_child_server(sys.argv[2], sys.argv[3]))
    unittest.main()
