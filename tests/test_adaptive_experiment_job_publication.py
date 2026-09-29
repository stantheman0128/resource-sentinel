"""Real two-ledger child publication with explicit synthetic native and wire.

The original authority, managed admission, pending guardian entry and wire MACs
are real. Native pipes/processes/readiness are test backends. This is source
regression evidence only, never Windows capability or daily activation proof.
"""
from dataclasses import replace
import hashlib
import hmac
import pickle
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_authority as authorities
from sentinel.adaptive import experiment_job_publication as module
from sentinel.adaptive.guardian import GuardianLaunchOwner, _PendingExecution
from sentinel.adaptive.ipc import _get_ipc_auth_record
from sentinel.adaptive.launch_transport import PrepareExecutionRequest
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_experiment_host_authority as fixture
from tests import test_adaptive_experiment_host_transport as wire
from tests import test_adaptive_guardian_launch as guardian_fixture
from tests import test_adaptive_guardian_lifecycle as lifecycle_fixture
from tests.test_adaptive_ipc import Clock, canonical, wire_frame


class ExperimentJobPublicationTests(unittest.TestCase):
    def setUp(self):
        self.host = fixture.ExperimentHostAuthorityTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.host.admit()
        self.authority, self.binding = self.host.guardian()
        self.store = self.host.store
        self.peer = self.host.fixture.child_process
        self.execution_id = self.host.execution_id
        self.epoch = "fixture-job-publication"
        recovery = self.host.fixture.coordinator.db_path.parent / "job-intent-recovery"
        recovery.mkdir()
        self.journal = RecoveryJournal(recovery, publisher=lifecycle_fixture.publish_fixture)
        self.owner = GuardianLaunchOwner(self.store, self.journal, guardian_epoch=self.epoch,
            authority=self.authority, guardian=self.host.guardian_process,
            job_factory=lambda *args, **kwargs: self.fail("unexpected native Create"),
            mutex_factory=lifecycle_fixture.Mutex)
        self.auth = _get_ipc_auth_record(self.store.db_path, self.execution_id)
        self.request = PrepareExecutionRequest(str(uuid4()), self.execution_id, self.host.snapshot.spec_hash,
                                             self.epoch, 0)
        self.deadline = guardian_fixture.Deadline()
        self.job_binding = None
        self.publications, self.connections = [], []
        self.fail_receipt = self.fail_close = False
        self.invalid_mac = False
        self.publish_daily = True
        for override in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()),
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False)):
            override.start()
            self.addCleanup(override.stop)

    def assert_no_fence(self):
        self.assertIsNone(self.authority._active)
        self.assertIsNone(self.store._policy.current_guard())
        self.assertIsNone(self.authority._daily_policy.current_guard())
        self.assertEqual(self.authority._reads, [])
        self.assertEqual(self.host.fixture.daily_transactions, [])

    def result(self, request):
        candidate = request.job_binding()
        if self.job_binding is None:
            self.job_binding = candidate
        self.assertEqual(candidate, self.job_binding)
        if self.publish_daily:
            with self.host.host.locked() as (conn, guard):
                value = ledger.publish_job_locked(conn, scope=self.host.host.scope_owner,
                    binding=self.job_binding, policy=self.host.host.policy, guard=guard)
                conn.commit()
        else:
            value = {key: getattr(candidate, key) for key in ledger.JobBinding.__dataclass_fields__}
            value.update(scope_id=request.manifest.scope_id, registered_revision=99)
        return module._result(value, request)

    def connection(self, *args, **kwargs):
        self.assert_no_fence()
        entry = self.owner._pending[self.execution_id]
        publication = entry.experiment_job_publication
        self.assertIsNotNone(publication)
        request = publication.request
        self.publications.append(publication)
        challenge = dict(version=1, kind="ExperimentJobChallenge", request_id=request.request_id,
            nonce=wire.NONCE, endpoint_id=request.manifest.endpoint.instance_id,
            server=request.manifest.endpoint.server_identity.to_dict(), client=request.manifest.child_identity.to_dict(),
            payload_sha256=request.payload_sha256)
        def mac(purpose, result=None):
            transcript = dict(domain="ResourceSentinel/experiment-job-ipc/v1/" + purpose,
                request=request.to_dict(), challenge=challenge)
            if purpose != "proof":
                transcript["result"] = result
            return hmac.new(wire.KEY, canonical(transcript), hashlib.sha256).hexdigest()
        def write(connection, message):
            self.assert_no_fence()
            if message["kind"] == "PublishExperimentJob":
                self.assertEqual(module.PublishExperimentJobRequest.from_dict(message), request)
                connection.enqueue(challenge)
            elif message["kind"] == "ExperimentJobProof":
                self.assertEqual(message["mac"], mac("proof"))
                result = self.result(request)
                response = dict(version=1, kind="ExperimentJobResult", request_id=request.request_id,
                    nonce=wire.NONCE, result=result,
                    mac="0" * 64 if self.invalid_mac else mac("result", result))
                connection.enqueue(response)
            elif message["kind"] == "ExperimentJobReceipt":
                if self.fail_receipt:
                    raise RuntimeError("synthetic_lost_receipt")
        connection = wire.Pipe(request.manifest.endpoint.server_identity, on_write=write,
                               on_read=lambda *_: self.assert_no_fence())
        if self.fail_close:
            connection.channel_error = RuntimeError("synthetic_close_unknown")
        self.connections.append(connection)
        return connection

    def publish(self):
        with patch.object(module.NativePipeConnection, "connect", side_effect=self.connection):
            self.owner.prepare_experiment_job_intent(self.request, self.peer, auth_record=self.auth,
                                                    deadline=self.deadline)
        return self.owner._pending[self.execution_id].experiment_job_publication

    def test_original_pending_name_published_before_any_native_create_or_isolated_scope(self):
        floor = self.host.host.fixture.assert_retained(self.host.host.owner)
        result = self.publish()
        entry = self.owner._pending[self.execution_id]
        self.assertIs(type(entry), _PendingExecution)
        self.assertFalse(entry.create_attempted)
        self.assertIsNone(entry.job)
        self.assertIsNone(entry.mutex)
        self.assertIsNone(self.store.query(self.execution_id, existing_path=True)["job_name"])
        self.assertEqual(result.request.job_name, entry.job_name)
        self.assertEqual(result.request.creation_nonce, entry.creation_nonce)
        self.assertTrue(result.attempts[0].exchange_complete)
        self.assertFalse(result.attempts[0].cleanup_pending)
        self.assertEqual(self.host.host.fixture.assert_retained(self.host.host.owner), floor)
        with self.assertRaises(TypeError):
            pickle.dumps(result)

    def test_lost_ack_replays_same_request_pending_entry_and_daily_job_revision(self):
        self.fail_receipt = True
        with self.assertRaises(module.ExperimentJobPublicationError):
            self.publish()
        entry = self.owner._pending[self.execution_id]
        publication = entry.experiment_job_publication
        request = publication.request
        floor = self.host.host.fixture.assert_retained(self.host.host.owner)
        self.assertFalse(publication.attempts[0].cleanup_pending)
        self.fail_receipt = False
        self.assertIs(self.publish(), publication)
        self.assertIs(publication.request, request)
        self.assertIs(self.owner._pending[self.execution_id], entry)
        self.assertEqual(len(publication.attempts), 2)
        self.assertEqual(self.host.host.fixture.assert_retained(self.host.host.owner), floor)
        self.assertFalse(entry.create_attempted)

    def test_positive_ack_is_cached_but_never_recreates_a_request(self):
        publication = self.publish()
        self.assertIs(self.publish(), publication)
        self.assertEqual(len(self.connections), 1)
        with self.assertRaisesRegex(module.ExperimentJobPublicationError, "original_pending_entry_required"):
            module.ExperimentJobPublication.prepare(self.binding, publication.entry, self.request)

    def test_unknown_channel_close_keeps_original_and_forbids_reconnect(self):
        self.fail_close = True
        with self.assertRaises(module.ExperimentJobPublicationError):
            self.publish()
        entry = self.owner._pending[self.execution_id]
        self.assertTrue(entry.experiment_job_publication.attempts[0].cleanup_pending)
        self.fail_close = False
        with self.assertRaisesRegex(module.ExperimentJobPublicationError, "original_cleanup_pending"):
            self.publish()
        self.assertEqual(len(self.connections), 1)
        self.assertFalse(entry.create_attempted)

    def test_changed_request_key_cannot_rebind_original_pending_entry(self):
        publication = self.publish()
        self.request = replace(self.request, request_id=str(uuid4()))
        with self.assertRaisesRegex(module.ExperimentJobPublicationError, "original_launch_request_changed"):
            self.publish()
        self.assertIs(self.owner._pending[self.execution_id].experiment_job_publication, publication)
        self.assertEqual(len(self.connections), 1)

    def test_changed_entry_nonce_or_native_binding_is_rejected_without_rpc(self):
        publication = self.publish()
        entry = publication.entry
        original = entry.creation_nonce
        entry.creation_nonce = uuid4().hex
        with self.assertRaises(module.ExperimentJobPublicationError):
            publication.publish()
        entry.creation_nonce = original
        backend = self.binding._process._backend
        self.binding._process._backend = object()
        try:
            with self.assertRaises(Exception):
                publication.publish()
        finally:
            self.binding._process._backend = backend
        self.assertEqual(len(self.connections), 1)

    def test_bad_mac_cannot_acknowledge_even_if_daily_intent_exists(self):
        self.invalid_mac = True
        with self.assertRaises(module.ExperimentJobPublicationError) as caught:
            self.publish()
        self.assertIn("result_authentication_failed", str(caught.exception.original_error))
        entry = self.owner._pending[self.execution_id]
        self.assertIsNone(entry.experiment_job_publication._result)
        self.assertFalse(entry.create_attempted)

    def test_parent_result_alone_is_not_create_authority(self):
        self.publish_daily = False
        self.publish()
        with self.assertRaises(Exception):
            with self.owner.experiment_launch_scope(self.request, self.peer, auth_record=self.auth,
                                                   deadline=self.deadline):
                self.owner.prepare_execution(self.request, self.peer, self.auth, self.deadline)
        self.assertFalse(self.owner._pending[self.execution_id].create_attempted)

    def test_drain_uses_actual_retirement_prepare_without_parent_or_new_work_scope(self):
        self.owner.begin_drain()
        with patch.object(self.owner, "prepare_experiment_job_intent", side_effect=AssertionError("RPC forbidden")), \
                patch.object(self.authority, "new_work_scope", side_effect=AssertionError("fresh scope forbidden")):
            with self.owner.experiment_launch_scope(self.request, self.peer, auth_record=self.auth,
                                                   deadline=self.deadline):
                result = self.owner.prepare_execution(self.request, self.peer, self.auth, self.deadline)
        self.assertFalse(result.launch_authorized)
        self.assertEqual(result.state, "RESERVED")
        entry = self.owner._pending[self.execution_id]
        self.assertTrue(entry.retirement_sealed)
        self.assertFalse(entry.create_attempted)
        self.assertIsNone(entry.job)
        self.assertIsNone(entry.experiment_job_publication)

    def test_request_digest_and_job_name_cannot_be_changed(self):
        publication = self.publish()
        encoded = publication.request.to_dict()
        encoded["payload_sha256"] = "0" * 64
        with self.assertRaisesRegex(module.ExperimentJobPublicationError, "payload_digest_mismatch"):
            module.PublishExperimentJobRequest.from_dict(encoded)
        with self.assertRaises(Exception):
            replace(publication.request, job_name="Local\\ResourceSentinel.Job.other")

    def test_closed_experiment_inventory_requires_draining_and_original_collections(self):
        with self.assertRaisesRegex(LifecycleError, "closed_custody_unavailable"):
            self.owner.closed_experiment_custody()
        self.owner.begin_drain()
        original = self.owner.closed_experiment_custody()
        self.assertEqual(original, ())
        self.assertIs(self.owner.closed_experiment_custody(), original)
        self.owner._experiment_closed = {}
        with self.assertRaisesRegex(LifecycleError, "closed_custody_unavailable"):
            self.owner.closed_experiment_custody()

    def test_live_or_lost_pending_entry_cannot_be_mistaken_for_closed_custody(self):
        publication = self.publish()
        self.owner.begin_drain()
        with self.assertRaisesRegex(LifecycleError, "closed_custody_unavailable"):
            self.owner.closed_experiment_custody()
        self.owner._pending.pop(self.execution_id)
        with self.assertRaisesRegex(LifecycleError, "closed_custody_unavailable"):
            self.owner.closed_experiment_custody()
        self.owner._pending[self.execution_id] = publication.entry
