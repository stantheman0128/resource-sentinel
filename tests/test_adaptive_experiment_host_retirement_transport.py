"""Real two-ledger parent/original actor custody with portable pipe backends.

Role release, accepted registrations, CreationAttempt and SQL are production
objects. Native Create/identity and completed pipe transfers are explicit test
providers. Client protocol tests replace only host-closure inspection with a
named observation fixture; separate inspection tests exercise actual types and
negative closure facts. None of these establish Windows capability evidence.
"""
from dataclasses import replace
from contextlib import closing
import hashlib
import hmac
import json
from pathlib import Path
import pickle
import sqlite3
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from sentinel.adaptive import experiment_host_retirement_transport as transport
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativeDeadline, NativePipeError
from tests import test_adaptive_experiment_role_release as role_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests.test_adaptive_ipc import Listener, canonical, wire_frame


REQUEST = "6fd2b426-8b0e-4a95-ae9e-84cf9e1c3271"


def wire_mac(key, purpose, request, challenge, result=None, *, family="experiment-host-retirement-ipc"):
    data = dict(domain="ResourceSentinel/" + family + "/v1/" + purpose,
                request=request.to_dict(), challenge=challenge)
    if purpose != "proof":
        data["result"] = result
    return hmac.new(key, canonical(data), hashlib.sha256).hexdigest()


class ExperimentRetirementTransportTests(role_fixture._RoleFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.bind_exchange = self.exchange(self.guardian)
        self.created, self.registration, _ = self.children[self.guardian.member_id]
        self.manifest = self.registration.manifest
        self.request = transport.PublishHostClosedRequest(self.manifest, REQUEST,
            canonical(dict(kind="guardian", jobs=[])))
        self.retirement = transport.ExperimentHostRetirementService(self.endpoint, self.owner)
        self.before = self.host.fixture.assert_retained(self.owner.demand)
        self.native_host, self.native_owners = object(), (object(),)
        self.binding = None
        override = patch.dict(transport._PUBLICATIONS, {}, clear=True)
        override.start()
        self.addCleanup(override.stop)

    def challenge(self):
        return dict(version=1, kind="ExperimentHostRetirementChallenge", request_id=REQUEST,
            nonce=pipe_fixture.NONCE, endpoint_id=self.endpoint.instance_id,
            server=self.endpoint.server_identity.to_dict(), client=self.manifest.child_identity.to_dict(),
            payload_sha256=self.request.payload_sha256)

    def envelope(self, kind, purpose, *, challenge=None, request=None, result=None, family=None):
        request = self.request if request is None else request
        challenge = self.challenge() if challenge is None else challenge
        payload = dict(actor_member_id=request.manifest.actor_member_id, payload_sha256=request.payload_sha256)
        if result is not None:
            payload = result
        value = dict(version=1, kind=kind, request_id=request.request_id, nonce=challenge["nonce"],
            mac=wire_mac(self.registration.auth_key, purpose, request, challenge,
                None if purpose == "proof" else payload,
                family=family or "experiment-host-retirement-ipc"))
        if kind == "ExperimentHostRetirementResult":
            value["result"] = payload
        return value

    def server_pipe(self, *, request=None, invalid_proof=False, invalid_receipt=False,
                    fail_final=False, dead_on_final=False, include_hello=True):
        request = self.request if request is None else request
        state = {}
        def write(connection, message):
            self.assert_settled()
            if message["kind"] == "ExperimentHostRetirementChallenge":
                state["challenge"] = message
                proof = self.envelope("ExperimentHostRetirementProof", "proof",
                    challenge=message, request=request)
                if invalid_proof:
                    proof["mac"] = "0" * 64
                connection.enqueue(proof)
            elif message["kind"] == "ExperimentHostRetirementResult":
                self.assertEqual(message["mac"], wire_mac(self.registration.auth_key, "result",
                    request, state["challenge"], message["result"]))
                receipt = self.envelope("ExperimentHostRetirementReceipt", "receipt",
                    challenge=state["challenge"], request=request)
                if invalid_receipt:
                    receipt["mac"] = "0" * 64
                connection.enqueue(receipt)
            elif message["kind"] == "ExperimentHostRetirementSettled":
                self.assertEqual(message["mac"], wire_mac(self.registration.auth_key, "settled",
                    request, state["challenge"], dict(actor_member_id=request.manifest.actor_member_id,
                                                    payload_sha256=request.payload_sha256)))
                if dead_on_final:
                    self.created.process._backend.state = IdentityStatus.DEAD
                    connection.backend.status = IdentityStatus.DEAD
                if fail_final:
                    raise OSError("fixture_lost_final_ack")
                connection.enqueue(self.envelope("ExperimentHostRetirementFinished", "finished",
                    challenge=state["challenge"], request=request))
        hello = dict(version=1, kind="ExperimentHostRetirementHello", request_id=request.request_id,
                     caller=request.manifest.child_identity.to_dict())
        incoming = (wire_frame(hello) if include_hello else b"") + wire_frame(request.to_dict())
        return pipe_fixture.Pipe(request.manifest.child_identity, incoming, on_write=write,
            on_read=lambda *_: self.assert_settled()), hello

    def client_pipe(self, *, final=True, bad_final=False, peer=None, family=None):
        frames = [self.challenge(), self.envelope("ExperimentHostRetirementResult", "result", family=family)]
        if final:
            settled = self.envelope("ExperimentHostRetirementSettled", "settled")
            if bad_final:
                settled["mac"] = "0" * 64
            frames.append(settled)
        return pipe_fixture.Pipe(self.endpoint.server_identity if peer is None else peer,
                                b"".join(wire_frame(value) for value in frames))

    def publish(self, pipe):
        if self.binding is None:
            self.binding = self.consume(self.guardian, self.bind_exchange)
        # Only closure inspection is synthetic here. The public factory retains
        # its real original child binding before connect; all IPC is production.
        with patch.object(child.os, "getpid", return_value=self.manifest.child_identity.pid), \
                patch.object(transport, "uuid4", return_value=UUID(REQUEST)), \
                patch.object(transport, "_closed_host", return_value=(self.request.closure_json, self.native_owners)), \
                patch.object(transport.NativePipeConnection, "connect", return_value=pipe):
            return transport.publish_host_closed(self.native_host, self.binding, self.created.process)

    def assert_floor(self):
        self.assertEqual(self.host.fixture.assert_retained(self.owner.demand), self.before)
        self.assertFalse(self.owner.demand._closed)

    def test_parent_accepts_exact_child_and_retains_typed_original_without_capacity_release(self):
        pipe, _ = self.server_pipe()
        self.retirement.serve_once(Listener(self.endpoint, pipe))
        receipts = transport.retained_retirements(self.owner)
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertIs(type(receipt), transport.AcceptedHostRetirement)
        self.assertIs(receipt.registration, self.registration)
        self.assertIs(receipt.actor[0], self.created)
        self.assertEqual(transport.validate_snapshot(receipt.snapshot()), receipt.snapshot())
        self.assertTrue(pipe.closed)
        self.assertEqual(self.retirement.attempts[0].cleanup_pending, False)
        self.assert_floor()

    def test_invalid_authentication_cannot_publish_receipt(self):
        pipe, _ = self.server_pipe(invalid_proof=True)
        with self.assertRaises(transport.ExperimentHostRetirementError) as raised:
            self.retirement.serve_once(Listener(self.endpoint, pipe))
        self.assertIn("authentication_failed", str(raised.exception.original_error))
        self.assertEqual(transport.retained_retirements(self.owner), ())
        self.assertFalse(self.retirement.attempts[0].cleanup_pending)
        self.assert_floor()

    def test_expired_transport_budget_cannot_accept_host_retirement(self):
        from sentinel.adaptive import pipe_windows
        pipe, _ = self.server_pipe()
        actual = pipe.on_write
        def consume_budget(connection, message):
            actual(connection, message)
            if message["kind"] == "ExperimentHostRetirementChallenge":
                pipe_windows._backend().now += 1001
        pipe.on_write = consume_budget
        with self.assertRaises(transport.ExperimentHostRetirementError):
            self.retirement.serve_once(Listener(self.endpoint, pipe), timeout_ms=1000)
        self.assertEqual(self.retirement._receipts, {})
        self.assertTrue(pipe.closed)
        self.assert_floor()

    def test_proof_from_a_previous_challenge_cannot_be_replayed(self):
        pipe, _ = self.server_pipe()
        actual = pipe.on_write
        def replay(connection, message):
            if message["kind"] == "ExperimentHostRetirementChallenge":
                connection.enqueue(self.envelope("ExperimentHostRetirementProof", "proof"))
            else:
                actual(connection, message)
        pipe.on_write = replay
        with patch.object(child.secrets, "token_hex", return_value="a" * 64), \
                self.assertRaises(transport.ExperimentHostRetirementError):
            self.retirement.serve_once(Listener(self.endpoint, pipe))
        self.assertEqual(self.retirement._receipts, {})
        self.assert_floor()

    def test_bad_receipt_retains_original_pending_publication(self):
        pipe, _ = self.server_pipe(invalid_receipt=True)
        with self.assertRaises(transport.ExperimentHostRetirementError):
            self.retirement.serve_once(Listener(self.endpoint, pipe))
        original = self.retirement._receipts[self.guardian.member_id]
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "exchange_unsettled"):
            original.assert_original(self.owner)
        good, _ = self.server_pipe()
        self.retirement.serve_once(Listener(self.endpoint, good))
        self.assertIs(transport.retained_retirements(self.owner)[0], original)
        self.assertEqual(len(original._attempts), 2)
        self.assert_floor()

    def test_lost_final_ack_reconciles_only_same_original_request(self):
        pipe, _ = self.server_pipe(fail_final=True)
        with self.assertRaises(transport.ExperimentHostRetirementError):
            self.retirement.serve_once(Listener(self.endpoint, pipe))
        original = self.retirement._receipts[self.guardian.member_id]
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "exchange_unsettled"):
            transport.retained_retirements(self.owner)
        other = replace(self.request, request_id=str(uuid4()))
        changed, _ = self.server_pipe(request=other)
        with self.assertRaises(transport.ExperimentHostRetirementError) as raised:
            self.retirement.serve_once(Listener(self.endpoint, changed))
        self.assertIn("original_retirement_changed", str(raised.exception.original_error))
        good, _ = self.server_pipe()
        self.retirement.serve_once(Listener(self.endpoint, good))
        self.assertIs(transport.retained_retirements(self.owner)[0], original)

    def test_child_may_exit_after_final_ack_without_retroactively_invalidating_receipt(self):
        pipe, _ = self.server_pipe(dead_on_final=True)
        self.retirement.serve_once(Listener(self.endpoint, pipe))
        receipt = transport.retained_retirements(self.owner)[0]
        self.created._backend.kernel.WaitForSingleObject = lambda *_: 0
        self.created._backend.kernel.CloseHandle = lambda *_: 1
        self.created.settle_native(self.owner)
        self.assertTrue(self.created.native_settled)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("SQL during retained metadata")), \
                patch.object(Path, "resolve", side_effect=AssertionError("filesystem during retained metadata")), \
                patch.object(VerifiedProcess, "observe", side_effect=AssertionError("native during retained metadata")):
            self.assertIs(receipt.assert_original(self.owner), receipt)
            self.assertIs(transport.retained_retirements(self.owner)[0], receipt)
        self.assert_floor()

    def test_unknown_peer_or_channel_close_blocks_receipt_consumption(self):
        for kind in ("peer_error", "channel_error"):
            with self.subTest(kind=kind):
                pipe, _ = self.server_pipe()
                setattr(pipe, kind, OSError("fixture_unknown_close"))
                with self.assertRaises(transport.ExperimentHostRetirementError):
                    self.retirement.serve_once(Listener(self.endpoint, pipe))
                with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "service_cleanup_pending"):
                    transport.retained_retirements(self.owner)
        self.assert_floor()

    def test_equal_registration_copy_and_copied_receipt_are_not_original_authority(self):
        pipe, _ = self.server_pipe()
        self.retirement.serve_once(Listener(self.endpoint, pipe))
        receipt = transport.retained_retirements(self.owner)[0]
        copy = object.__new__(transport.AcceptedHostRetirement)
        copy.__dict__.update(receipt.__dict__)
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "original_receipt_changed"):
            copy.assert_original(self.owner)
        with self.assertRaises(TypeError):
            pickle.dumps(receipt)
        with self.assertRaises(transport.ExperimentHostRetirementError):
            transport.AcceptedHostRetirement.assert_original(receipt.snapshot(), self.owner)
        old = self.owner._child_registrations[self.guardian.member_id]
        self.owner._child_registrations[self.guardian.member_id] = (old[0], replace(old[1]))
        try:
            with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "original_registration_changed"):
                receipt.assert_original(self.owner)
        finally:
            self.owner._child_registrations[self.guardian.member_id] = old

    def test_parent_mux_common_attempt_is_retained_once_and_requires_outer_close(self):
        pipe, hello = self.server_pipe(include_hello=False)
        attempt = child._Attempt()
        attempt.channel_started, attempt.channel_origin = True, object()
        deadline = NativeDeadline.after_ms(1000)
        with child._settled_scope(pipe, attempt, "channel") as connection:
            self.retirement._serve_connection(connection, deadline, attempt, hello=hello)
            with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "service_cleanup_pending"):
                transport.retained_retirements(self.owner)
        attempt.seal()
        self.assertEqual(self.retirement.attempts, (attempt,))
        self.assertEqual(len(transport.retained_retirements(self.owner)), 1)

    def test_client_needs_final_authenticated_settled_ack_before_success(self):
        with self.assertRaises(transport.ExperimentHostRetirementError) as missing:
            self.publish(self.client_pipe(final=False))
        original = missing.exception.experiment_host_retirement_publication
        self.assertIsNone(original._result)
        with self.assertRaises(transport.ExperimentHostRetirementError) as bad:
            self.publish(self.client_pipe(bad_final=True))
        self.assertIs(bad.exception.experiment_host_retirement_publication, original)
        good = self.client_pipe()
        self.assertIs(self.publish(good), original)
        with patch.object(child.os, "getpid", return_value=self.manifest.child_identity.pid):
            self.assertFalse(original.custody_pending)
            self.binding.close()
            # Model the metadata left by positive bootstrap self-handle close;
            # this fixture still owns its normal cleanup callback afterward.
            with patch.object(self.created.process, "_handle", None), \
                    patch.object(VerifiedProcess, "observe", side_effect=AssertionError("metadata observed native")):
                self.assertFalse(original.custody_pending)
        self.assertEqual(len(original.attempts), 3)
        self.assertNotIn(self.registration.auth_key.hex(), str(good.writes))
        self.assert_floor()

    def test_wrong_parent_sends_no_credential_or_request_and_wrong_domain_is_rejected(self):
        wrong = replace(self.endpoint.server_identity, created_filetime_100ns=self.endpoint.server_identity.created_filetime_100ns + 1)
        pipe = self.client_pipe(peer=wrong)
        with self.assertRaises(transport.ExperimentHostRetirementError):
            self.publish(pipe)
        self.assertEqual(pipe.writes, [])
        with self.assertRaises(transport.ExperimentHostRetirementError) as bad:
            self.publish(self.client_pipe(family="experiment-backing-ipc"))
        self.assertIn("result_authentication_failed", str(bad.exception.original_error))

    def test_unknown_client_close_never_reconnects_or_reports_settled(self):
        pipe = self.client_pipe()
        pipe.channel_error = OSError("fixture_unknown_channel_close")
        with self.assertRaises(transport.ExperimentHostRetirementError) as raised:
            self.publish(pipe)
        original = raised.exception.experiment_host_retirement_publication
        next_pipe = self.client_pipe()
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "original_cleanup_pending"):
            self.publish(next_pipe)
        self.assertEqual(next_pipe.writes, [])
        with patch.object(child.os, "getpid", return_value=self.manifest.child_identity.pid):
            self.assertTrue(original.custody_pending)
        self.assertEqual(len(original.attempts), 1)

    def test_snapshot_and_wire_are_strict_bounded_data(self):
        self.assertEqual(transport.PublishHostClosedRequest.from_dict(self.request.to_dict()), self.request)
        for alter in (lambda data: data.update(closed=True),
                      lambda data: data["closure"].update(unknown=True),
                      lambda data: data.update(payload_sha256="0" * 64),
                      lambda data: data.update(request_id=self.manifest.request_id)):
            data = self.request.to_dict()
            alter(data)
            with self.assertRaises((transport.ExperimentHostRetirementError, IpcError)):
                transport.PublishHostClosedRequest.from_dict(data)


class ClosedHostInspectionTests(unittest.TestCase):
    def test_unknown_or_caller_supplied_host_cannot_mint_publication(self):
        for host in (True, {"closed": True}, SimpleNamespace(closed=True)):
            with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "original_child_required"):
                transport.publish_host_closed(host, object(), object())

    def test_closed_identity_requires_positive_native_close(self):
        backend = pipe_fixture.Backend(pipe_fixture.CHILD)
        process = VerifiedProcess(backend, 901, pipe_fixture.CHILD)
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "native_cleanup_pending"):
            transport._closed_process(process)
        process.close()
        transport._closed_process(process)
        process._close_outcome_unknown = True
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "native_cleanup_pending"):
            transport._closed_process(process)

    def test_telemetry_delivery_error_is_not_native_custody_but_unknown_files_are(self):
        from sentinel.adaptive.telemetry import ResidentTelemetry, SharedTelemetryStore
        sink = object.__new__(ResidentTelemetry)
        store = sink.store = object.__new__(SharedTelemetryStore)
        store._owners, store._quarantined, store._quarantine_error = {}, False, None
        sink._thread = threading.Thread(target=lambda: None)
        sink._stop, sink._done = True, True
        sink._error = OSError("fixture_write_failure_after_positive_close")
        host = SimpleNamespace(telemetry=sink)
        transport._telemetry_closed(sink, host)
        store._quarantined = True
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "telemetry_cleanup_pending"):
            transport._telemetry_closed(sink, host)

    def test_helper_inspector_uses_actual_mode_and_original_registration_completion(self):
        from sentinel.adaptive.helper_control_host import OperationalHelperHost
        host = object.__new__(OperationalHelperHost)
        host._experiment_child_binding = binding = object()
        host._experiment_role_spec = spec = object()
        host._closed = False
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "helper_cleanup_pending"):
            transport._helper_closed(host, binding, spec)

    def test_shallow_copied_helper_cannot_replace_the_original_bootstrap_host(self):
        from sentinel.adaptive.helper_control_host import OperationalHelperHost
        from sentinel.adaptive.experiment_child_host import ExperimentChildHost
        original = object.__new__(OperationalHelperHost)
        copied = object.__new__(OperationalHelperHost)
        bootstrap = object.__new__(ExperimentChildHost)
        binding = SimpleNamespace(_experiment_bootstrap_owner=bootstrap)
        spec = object()
        original.__dict__.update(_experiment_child_binding=binding, _experiment_role_spec=spec,
            _closed=True, _started=False, _operator_ready=True, _cleanup_started=True,
            _drain_requested=True, _startup_error=None, _cleanup_error=None, _operator_error=None,
            process=None, parent_process=None, operator_listener=None, _listener_factory=None,
            _observer_factory=None, _parent_opener=None)
        copied.__dict__.update(original.__dict__)
        bootstrap.host, bootstrap.binding, bootstrap.role = original, binding, spec
        bootstrap.authenticated = bootstrap.dispatched = bootstrap.host_closed = True
        with self.assertRaisesRegex(transport.ExperimentHostRetirementError, "original_helper_required"):
            transport._helper_closed(copied, binding, spec)


class OriginalAdmissionRetirementTests(unittest.TestCase):
    """Actual two-ledger admission/cancel owners; launcher metadata fixture only.

The production wrapper inspector checks its factory's original binding first.
Here that outer host construction is isolated so real cancellation, rollback,
credential destruction and retained SQL cleanup can be tested without cmd.exe.
"""
    def setUp(self):
        from tests import test_adaptive_experiment_partition_admission as fixture
        from sentinel.adaptive.launcher import ManagedLauncher, _ExperimentWrapperBinding
        self.fx = fixture.ExperimentPartitionAdmissionTests()
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.context, self.snapshot, self.partition = self.fx.context, self.fx.snapshot, self.fx.adapter
        # Replace the fixture's simple identity provider before admission with
        # the production native owner class and its explicit synthetic backend.
        self.context._process = VerifiedProcess(pipe_fixture.Backend(self.snapshot.wrapper_identity),
                                                908, self.snapshot.wrapper_identity)
        self.original = object.__new__(_ExperimentWrapperBinding)
        self.original.context, self.original.snapshot, self.original.partition = self.context, self.snapshot, self.partition
        self.launcher = object.__new__(ManagedLauncher)
        self.launcher.__dict__.update(admission=self.context, _snapshot=self.snapshot, coordinator=self.partition,
            _prepare_attempted=False, _claim_attempted=False, _create_attempted=False, _bound=False,
            _prepared=None, _claim=None, _root=None, process=None, job=None, _retired_result=None,
            _submitted=False, _admitted=None, _abandon_result=None, _abandon_cancel_target=None)
        self.before = self.fx.host.fixture.assert_retained(self.fx.host.owner)

    def cancel_reserved(self):
        from sentinel.adaptive.launcher import ManagedLauncher
        result = self.partition.admit_managed(self.context)
        self.launcher._submitted, self.launcher._admitted = True, dict(result)
        ManagedLauncher._abandon_admission(self.launcher)
        self.context.close()
        return transport._admission_retirement(self.original, self.launcher)

    def assert_daily_charged(self):
        self.assertEqual(self.fx.host.fixture.assert_retained(self.fx.host.owner), self.before)

    def test_original_reserved_cancellation_is_distinct_from_guardian_job_retirement(self):
        result = self.cancel_reserved()
        self.assertEqual(result["kind"], "reserved_cancelled")
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(result["reservation_id"], self.partition.reservation_id)
        self.assertEqual(result["admission_binding_hash"], self.snapshot.binding_hash)
        self.assertEqual(self.fx.rows("reservations"), [])
        self.assertEqual(self.fx.rows("managed_executions")[0]["state_revision"], result["state_revision"])
        self.assertEqual(len(self.fx.rows("executions")), 1)
        self.assert_daily_charged()

    def test_reserved_false_foreign_and_missing_original_evidence_is_rejected(self):
        self.cancel_reserved()
        alterations = (
            (self.context, "_cancel_target", (self.partition.db_path, "foreign-reservation")),
            (self.context, "_prepare_attempted", True),
            (self.context, "_claim_exported", True),
            (self.context, "_abandon_error", OSError("fixture_unknown_close")),
            (self.context, "_claim_token", "not-destroyed"),
            (self.launcher, "_abandon_result", None),
            (self.launcher, "_abandon_result", {**self.launcher._abandon_result, "cancelled": 1}),
            (self.launcher, "_abandon_result", {**self.launcher._abandon_result, "execution_id": str(uuid4())}),
        )
        for owner, name, value in alterations:
            with self.subTest(name=name), patch.object(owner, name, value), \
                    self.assertRaises(transport.ExperimentHostRetirementError):
                transport._admission_retirement(self.original, self.launcher)
        self.assert_daily_charged()

    def test_uncertain_or_foreign_submission_transaction_cannot_retire(self):
        self.cancel_reserved()
        transaction = self.context._submission_transaction
        for change in ({"connection_closed": False}, {"execution_id": str(uuid4())},
                       {"db_path": self.partition.db_path.with_name("foreign.db")}):
            with self.subTest(change=change), patch.dict(transaction, change), \
                    self.assertRaises(transport.ExperimentHostRetirementError):
                transport._admission_retirement(self.original, self.launcher)
        with closing(sqlite3.connect(":memory:")) as open_connection, \
                patch.dict(transaction, {"connection": open_connection, "connection_closed": True}), \
                self.assertRaisesRegex(transport.ExperimentHostRetirementError, "transaction_changed"):
            transport._admission_retirement(self.original, self.launcher)
        foreign_closed = sqlite3.connect(":memory:")
        foreign_closed.close()
        with patch.dict(transaction, {"connection": foreign_closed}), \
                self.assertRaisesRegex(transport.ExperimentHostRetirementError, "transaction_changed"):
            transport._admission_retirement(self.original, self.launcher)
        original = self.context._submission_transaction_original
        changes = (
            ("_submission_transaction", dict(transaction)),
            ("_submission_transaction_original", None),
            ("_submission_transaction_original", (object(), *original[1:])),
            ("_submission_transaction_original", (*original[:2], foreign_closed, *original[3:])),
        )
        for name, value in changes:
            with self.subTest(pin=name), patch.object(self.context, name, value), \
                    self.assertRaisesRegex(transport.ExperimentHostRetirementError, "transaction_changed"):
                transport._admission_retirement(self.original, self.launcher)

    def test_known_never_submitted_requires_no_submission_or_cancellation_attempt(self):
        self.context.close()
        result = transport._admission_retirement(self.original, self.launcher)
        self.assertEqual((result["kind"], result["abandon_kind"]), ("never_admitted", "NEVER_SUBMITTED"))
        with patch.object(self.context, "_submitted", True), \
                self.assertRaisesRegex(transport.ExperimentHostRetirementError, "never_submitted_unverified"):
            transport._admission_retirement(self.original, self.launcher)
        self.assertEqual(self.fx.rows("managed_executions"), [])
        self.assert_daily_charged()

    def test_actual_rolled_back_submission_has_original_abandonment_transaction(self):
        from sentinel.adaptive.launcher import ManagedLauncher
        with closing(sqlite3.connect(self.partition.db_path)) as conn:
            conn.execute("CREATE TRIGGER fixture_reject BEFORE INSERT ON managed_executions "
                         "BEGIN SELECT RAISE(ABORT,'fixture_rejected'); END")
            conn.commit()
        self.launcher._submitted = True
        with self.assertRaises(sqlite3.DatabaseError):
            self.partition.admit_managed(self.context)
        ManagedLauncher._abandon_admission(self.launcher)
        self.context.close()
        result = transport._admission_retirement(self.original, self.launcher)
        self.assertEqual(result["abandon_kind"], "SUBMISSION_REJECTED")
        self.assertTrue(self.context._submission_transaction["rolled_back"])
        self.assertTrue(self.context._abandon_transaction["connection_closed"])
        self.assertEqual(self.fx.rows("managed_executions"), [])
        self.assert_daily_charged()
        for change in ({"connection_closed": False}, {"commit_attempted": False}):
            with self.subTest(change=change), patch.dict(self.context._abandon_transaction, change), \
                    self.assertRaises(transport.ExperimentHostRetirementError):
                transport._admission_retirement(self.original, self.launcher)
        with patch.dict(self.context._submission_transaction, {"commit_attempted": True}), \
                self.assertRaisesRegex(transport.ExperimentHostRetirementError, "submission_rejection_unverified"):
            transport._admission_retirement(self.original, self.launcher)
        transaction = self.context._abandon_transaction
        foreign_closed = sqlite3.connect(":memory:")
        foreign_closed.close()
        with patch.dict(transaction, {"connection": foreign_closed}), \
                self.assertRaisesRegex(transport.ExperimentHostRetirementError, "transaction_changed"):
            transport._admission_retirement(self.original, self.launcher)
        original = self.context._abandon_transaction_original
        changes = (
            ("_abandon_transaction", dict(transaction)),
            ("_abandon_transaction_original", None),
            ("_abandon_transaction_original", (object(), *original[1:])),
            ("_abandon_transaction_original", (*original[:2], foreign_closed, *original[3:])),
        )
        for name, value in changes:
            with self.subTest(pin=name), patch.object(self.context, name, value), \
                    self.assertRaisesRegex(transport.ExperimentHostRetirementError, "transaction_changed"):
                transport._admission_retirement(self.original, self.launcher)

    def test_optional_wire_union_is_strict_and_exact_execution_bound(self):
        retired = self.cancel_reserved()
        closure = dict(kind="wrapper", execution_id=self.snapshot.execution_id, native_owners_closed=0,
            publication_request_id=str(uuid4()), publication_sha256="a" * 64, launcher_phase="CLOSED",
            admission_retirement=retired)
        transport._closure(closure, "wrapper")
        for alter in ({"state_revision": True}, {"execution_id": str(uuid4())},
                      {"native_closed": True}, {"kind": "somehow_gone"}):
            with self.subTest(alter=alter), patch.dict(retired, alter), \
                    self.assertRaises(transport.ExperimentHostRetirementError):
                transport._closure(closure, "wrapper")


if __name__ == "__main__":
    unittest.main()
