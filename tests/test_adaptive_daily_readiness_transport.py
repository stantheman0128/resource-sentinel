"""Synthetic pipe/retained-peer tests, not native daily activation evidence.

The real closed protocol runs against completed in-memory transfers. Explicit
fake backends supply VerifiedProcess liveness; no native API, daily ledger,
configuration, generation activation or POLICY operation is used here.
"""
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeError
from tests.test_adaptive_ipc import Clock, Connection, Listener, wire_frame


LOGON = "S-1-5-5-100-200"
CALLER = ProcessIdentity(os.getpid(), 134343072000000001, LOGON)
SERVER = ProcessIdentity(os.getpid() + 1, 134343072000000002, LOGON)
ENDPOINT = "5ec1e614-9dd9-47db-b54b-8ec9767b36aa"
GENERATION = "0aadef58-91ae-44d4-a31f-0ec97975b146"
REQUEST = "47fe8a64-1e71-45b1-b7a7-10361e4b4d65"
SOURCE = "a" * 64
CONFIG = "b" * 64
LEDGER = transport.LedgerFileIdentity(7, 10000000000000000001)


def binding(**changes):
    return {"generation": GENERATION, "source_digest": SOURCE, "config_digest": CONFIG,
            "ledger_identity": LEDGER.to_dict(), **changes}


def hello(**changes):
    return {"version": 1, "kind": "DailyReadinessHello", "request_id": REQUEST,
            "caller": CALLER.to_dict(), **changes}


def request(**changes):
    return {"version": 1, "kind": "DailyReadinessAssert", "request_id": REQUEST,
            **binding(), **changes}


def response(**changes):
    return {"version": 1, "kind": "DailyReadinessReady", "request_id": REQUEST,
            "endpoint_id": ENDPOINT, "server": SERVER.to_dict(), "client": CALLER.to_dict(),
            "nonce": "c" * 64, **binding(), **changes}


class ProcessBackend:
    def __init__(self):
        self.status = IdentityStatus.ALIVE

    def wait(self, _handle):
        if self.status is IdentityStatus.UNKNOWN:
            raise IdentityUnavailable("synthetic_wait_unavailable")
        return self.status


class Loopback(Connection):
    def __init__(self, peer, *, pump=None):
        super().__init__(peer)
        self.pump = pump

    def read_exact(self, size, deadline):
        if not self.incoming and self.pump is not None:
            pump, self.pump = self.pump, None
            pump()
        return super().read_exact(size, deadline)


class DailyReadinessTransportTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        for replacement in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock),
                patch.object(transport, "uuid4", return_value=REQUEST)):
            replacement.start()
            self.addCleanup(replacement.stop)
        self.caller_backend, self.server_backend = ProcessBackend(), ProcessBackend()
        self.caller = VerifiedProcess(self.caller_backend, 111, CALLER)
        self.server = VerifiedProcess(self.server_backend, 222, SERVER)
        self.endpoint = NativePipeEndpoint(LOGON, ENDPOINT, SERVER)
        with patch.object(generation, "_ledger_identity", return_value=(LEDGER.st_dev, LEDGER.st_ino)):
            self.owner = generation.DailyGenerationOwner(_token=generation._TOKEN,
                process=self.server, cohort=None, manifest=SimpleNamespace(digest=SOURCE),
                source_root=None, ledger_path=None)
        self.owner.generation = GENERATION
        self.owner._config_digest = CONFIG
        self.owner.ledger_identity = (LEDGER.st_dev, LEDGER.st_ino)
        self.owner.readiness_endpoint = self.endpoint
        with patch.object(transport.os, "getpid", return_value=SERVER.pid):
            self.service = transport.DailyReadinessService(self.endpoint, self.owner)
        self.client = transport.DailyReadinessClient(self.endpoint, self.caller)
        self.ready_calls = []
        self.connection = None

    def synthetic_ready(self, owner):
        self.assertIs(owner, self.owner)
        self.assertTrue(self.connection.peer_held)
        self.ready_calls.append(owner)

    def serve(self, connection, *, ready=None, timeout_ms=1000):
        self.connection = connection
        ready = self.synthetic_ready if ready is None else ready
        with patch.object(transport.os, "getpid", return_value=SERVER.pid), \
                patch.object(generation.DailyGenerationOwner, "assert_ready", lambda owner: ready(owner)):
            return self.service.serve_once(Listener(self.endpoint, connection), timeout_ms=timeout_ms)

    def server_connection(self, *, hello_value=None, request_value=None, peer=CALLER, **kwargs):
        return Connection(peer, wire_frame(hello() if hello_value is None else hello_value) +
                          wire_frame(request() if request_value is None else request_value), **kwargs)

    def client_connection(self, *, reply=None, peer=SERVER, on_write=None):
        def respond(connection, message):
            if on_write is not None:
                on_write(connection, message)
            if message["kind"] == "DailyReadinessAssert":
                connection.enqueue(response() if reply is None else reply)
        return Connection(peer, on_write=respond)

    def call(self, connection, **changes):
        values = dict(generation=GENERATION, source_digest=SOURCE, config_digest=CONFIG,
                      ledger_identity=LEDGER)
        with patch.object(transport.NativePipeConnection, "connect", return_value=connection) as connect:
            result = self.client.assert_ready(**(values | changes))
            self.assertEqual(connect.call_count, 1)
            return result

    def test_full_client_service_exchange_holds_peer_and_settles_before_success(self):
        server_end = Loopback(CALLER)
        client_end = Loopback(SERVER, pump=lambda: self.serve(server_end))
        server_end.on_write = lambda _connection, message: client_end.enqueue(message)
        client_end.on_write = lambda _connection, message: server_end.enqueue(message)
        self.assertIsNone(self.call(client_end))
        self.assertEqual(self.ready_calls, [self.owner])
        self.assertTrue(client_end.closed)
        self.assertTrue(server_end.closed)
        self.assertFalse(client_end.peer_held)
        self.assertEqual(client_end.verified, [SERVER])
        self.assertEqual(server_end.verified, [CALLER])

    def test_client_rejects_reused_pid_different_creation_before_writing(self):
        connection = self.client_connection(peer=replace(SERVER,
            created_filetime_100ns=SERVER.created_filetime_100ns + 1))
        with self.assertRaisesRegex(transport.DailyReadinessError, "peer_unverified"):
            self.call(connection)
        self.assertEqual(connection.writes, [])

    def test_server_authenticates_hello_before_full_request(self):
        connection = self.server_connection(peer=replace(CALLER,
            created_filetime_100ns=CALLER.created_filetime_100ns + 1))
        with self.assertRaises(transport.DailyReadinessError):
            self.serve(connection)
        self.assertEqual(len(connection.reads), 2)
        self.assertEqual(self.ready_calls, [])

    def test_oversized_hello_does_not_read_body(self):
        connection = Connection(CALLER, struct.pack("<I", transport.MAX_HELLO_BYTES + 1))
        with self.assertRaisesRegex(transport.DailyReadinessError, "frame_too_large"):
            self.serve(connection)
        self.assertEqual(connection.reads, [4])
        self.assertEqual(connection.verified, [])

    def test_oversized_authenticated_request_does_not_read_body(self):
        connection = Connection(CALLER, wire_frame(hello()) +
                                struct.pack("<I", transport.MAX_MESSAGE_BYTES + 1))
        with self.assertRaisesRegex(transport.DailyReadinessError, "frame_too_large"):
            self.serve(connection)
        self.assertEqual(len(connection.reads), 3)
        self.assertEqual(connection.verified, [CALLER])
        self.assertEqual(self.ready_calls, [])

    def test_unknown_request_fields_and_write_operation_are_refused(self):
        for changed in (request(allow=True), request(kind="DailyGenerationInstall"),
                        request(version=True), request(generation="not-a-uuid"),
                        request(source_digest="A" * 64), request(config_digest=None),
                        request(ledger_identity={"st_dev": 7, "st_ino": 10})):
            with self.subTest(changed=changed), self.assertRaises(transport.DailyReadinessError):
                self.serve(self.server_connection(request_value=changed))
        self.assertEqual(self.ready_calls, [])

    def test_duplicate_json_key_is_refused(self):
        payload = b'{"version":1,"version":1}'
        connection = Connection(CALLER, struct.pack("<I", len(payload)) + payload)
        with self.assertRaisesRegex(transport.DailyReadinessError, "invalid_json"):
            self.serve(connection)
        self.assertEqual(self.ready_calls, [])

    def test_request_id_must_match_authenticated_hello(self):
        other = "05b6a036-a6cd-49ae-8125-cfd43c996aa0"
        with self.assertRaisesRegex(transport.DailyReadinessError, "request_mismatch"):
            self.serve(self.server_connection(request_value=request(request_id=other)))
        self.assertEqual(self.ready_calls, [])

    def test_owner_not_activated_cannot_be_replaced_by_matching_request(self):
        self.assertFalse(self.owner._activated)
        connection = self.server_connection()
        with patch.object(transport.os, "getpid", return_value=SERVER.pid), \
                self.assertRaisesRegex(transport.DailyReadinessError, "not_activated"):
            self.service.serve_once(Listener(self.endpoint, connection))
        self.assertEqual(connection.writes, [])

    def test_owner_failure_never_sends_ready(self):
        def refused(_owner):
            raise generation.DailyGenerationUnavailable("daily_config_changed")
        connection = self.server_connection()
        with self.assertRaisesRegex(transport.DailyReadinessError, "daily_config_changed"):
            self.serve(connection, ready=refused)
        self.assertEqual(connection.writes, [])

    def test_service_compares_all_bindings_after_original_ready(self):
        for key, changed in (("generation", "05b6a036-a6cd-49ae-8125-cfd43c996aa0"),
                             ("source_digest", "d" * 64), ("config_digest", "d" * 64),
                             ("ledger_identity", transport.LedgerFileIdentity(7, 8).to_dict())):
            with self.subTest(key=key):
                connection = self.server_connection(request_value=request(**{key: changed}))
                with self.assertRaisesRegex(transport.DailyReadinessError, "binding_mismatch"):
                    self.serve(connection)
                self.assertEqual(connection.writes, [])
        self.assertEqual(len(self.ready_calls), 4)

    def test_client_refuses_changed_reply_fields(self):
        for key, changed in (("generation", "05b6a036-a6cd-49ae-8125-cfd43c996aa0"),
                             ("source_digest", "d" * 64), ("config_digest", "d" * 64),
                             ("ledger_identity", transport.LedgerFileIdentity(7, 8).to_dict()),
                             ("endpoint_id", GENERATION), ("request_id", GENERATION),
                             ("server", CALLER.to_dict()), ("client", SERVER.to_dict()),
                             ("nonce", "invalid"), ("ready", True)):
            with self.subTest(key=key), self.assertRaises(transport.DailyReadinessError):
                self.call(self.client_connection(reply=response(**{key: changed})))

    def test_server_death_after_reply_cannot_return_success(self):
        def die_after_read(connection, _size):
            connection.retained.observation = IdentityObservation(SERVER, IdentityStatus.DEAD)
        connection = self.client_connection()
        connection.on_read = die_after_read
        with self.assertRaises(transport.DailyReadinessError):
            self.call(connection)

    def test_peer_pid_change_after_reply_is_refused(self):
        connection = self.client_connection()
        connection.on_read = lambda item, _size: setattr(item, "pid", SERVER.pid + 1)
        with self.assertRaises(transport.DailyReadinessError):
            self.call(connection)

    def test_owner_verification_exceeding_deadline_does_not_publish(self):
        def slow(owner):
            self.synthetic_ready(owner)
            self.clock.now += 1000
        connection = self.server_connection()
        with self.assertRaisesRegex(transport.DailyReadinessError, "deadline_exceeded"):
            self.serve(connection, ready=slow)
        self.assertEqual(connection.writes, [])

    def test_client_deadline_checked_after_channel_cleanup(self):
        clock = self.clock
        class SlowClose(Connection):
            def __exit__(self, *_):
                super().__exit__()
                clock.now += 1000
        connection = SlowClose(SERVER, wire_frame(response()))
        with self.assertRaisesRegex(transport.DailyReadinessError, "deadline_exceeded"):
            self.call(connection)

    def test_unknown_channel_cleanup_preserves_original_custody(self):
        cause = NativePipeError("pipe_handle_close_failed")
        class UnknownClose(Connection):
            def __exit__(self, *_):
                raise cause
        connection = UnknownClose(SERVER, wire_frame(response()))
        with self.assertRaises(transport.DailyReadinessError) as raised:
            self.call(connection)
        self.assertIs(raised.exception._daily_readiness_cause, cause)
        self.assertIs(raised.exception._daily_readiness_connection, connection)
        self.assertIs(raised.exception._daily_readiness_owner, self.client)

    def test_unknown_peer_cleanup_prevents_success(self):
        class UnknownPeerClose(Connection):
            @contextmanager
            def verified_peer(self, expected):
                with super().verified_peer(expected) as peer:
                    yield peer
                raise NativePipeError("pipe_peer_close_failed")
        connection = UnknownPeerClose(SERVER, wire_frame(response()))
        with self.assertRaisesRegex(transport.DailyReadinessError, "pipe_peer_close_failed"):
            self.call(connection)

    def test_baseexception_does_not_discard_connection_owner(self):
        class Interrupted(Connection):
            def read_exact(self, *_):
                raise KeyboardInterrupt()
        connection = Interrupted(SERVER)
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.call(connection)
        self.assertIs(raised.exception._daily_readiness_connection, connection)
        self.assertIs(raised.exception._daily_readiness_owner, self.client)

    def test_no_identity_dict_or_generic_callback_is_accepted(self):
        with self.assertRaisesRegex(transport.DailyReadinessError, "current_process_required"):
            transport.DailyReadinessClient(self.endpoint, CALLER)
        with self.assertRaisesRegex(transport.DailyReadinessError, "original_owner_required"):
            transport.DailyReadinessService(self.endpoint, lambda: True)

    def test_other_process_handle_is_not_current_caller(self):
        with self.assertRaisesRegex(transport.DailyReadinessError, "current_process_required"):
            transport.DailyReadinessClient(self.endpoint, self.server)

    def test_service_requires_preminted_original_owner_endpoint(self):
        other = NativePipeEndpoint(LOGON, GENERATION, SERVER)
        with self.assertRaisesRegex(transport.DailyReadinessError, "endpoint_mismatch"):
            transport.DailyReadinessService(other, self.owner)

    def test_service_rejects_replacement_of_original_process_object(self):
        self.owner.process = VerifiedProcess(self.server_backend, 333, SERVER)
        with patch.object(transport.os, "getpid", return_value=SERVER.pid), \
                self.assertRaisesRegex(transport.DailyReadinessError, "original_owner_required"):
            self.service.serve_once(Listener(self.endpoint, self.server_connection()))

    def test_unknown_caller_liveness_prevents_connect(self):
        self.caller_backend.status = IdentityStatus.UNKNOWN
        with patch.object(transport.NativePipeConnection, "connect") as connect, \
                self.assertRaisesRegex(transport.DailyReadinessError, "process_unavailable"):
            self.client.assert_ready(GENERATION, SOURCE, CONFIG, LEDGER)
        connect.assert_not_called()

    def test_invalid_timeout_never_connects(self):
        for timeout in (True, 0, 5001):
            with self.subTest(timeout=timeout), \
                    patch.object(transport.NativePipeConnection, "connect") as connect, \
                    self.assertRaises(NativePipeError):
                self.client.assert_ready(GENERATION, SOURCE, CONFIG, LEDGER, timeout_ms=timeout)
            connect.assert_not_called()


class LedgerFileIdentityTests(unittest.TestCase):
    def test_roundtrip_uses_exact_decimal_file_identity(self):
        self.assertEqual(transport.LedgerFileIdentity.from_dict(LEDGER.to_dict()), LEDGER)
        self.assertIsInstance(LEDGER.to_dict()["st_ino"], str)

    def test_invalid_and_unstable_file_identity_fields_are_rejected(self):
        for value in ({"st_dev": "7", "st_ino": "0"},
                      {"st_dev": "7", "st_ino": "01"},
                      {"st_dev": True, "st_ino": "5"},
                      {"st_dev": "7", "st_ino": "5", "size": "5"},
                      {"st_dev": "7", "st_ino": str(1 << 128)}):
            with self.subTest(value=value), self.assertRaises(transport.DailyReadinessError):
                transport.LedgerFileIdentity.from_dict(value)

    def test_capture_reads_existing_file_without_changing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolated.db"
            path.write_bytes(b"isolated fixture")
            observed = transport.LedgerFileIdentity.capture(path)
            info = path.stat()
            self.assertEqual(observed, transport.LedgerFileIdentity(info.st_dev, info.st_ino))
            self.assertEqual(path.read_bytes(), b"isolated fixture")

    def test_capture_never_creates_missing_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "absent.db"
            with self.assertRaisesRegex(transport.DailyReadinessError, "identity_unavailable"):
                transport.LedgerFileIdentity.capture(path)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
