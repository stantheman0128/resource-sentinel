"""Authenticated dispatch through the original two-ledger guardian authority.

The LaunchService, guardian request scope, authority, admission and SQLite
ledgers are real. Completed pipe transfers, native identities/readiness and the
fixed mutation bodies are explicit fixtures. These tests establish dispatch
and lock ordering, not Job creation, native recovery or a Windows gate.
"""
from contextlib import contextmanager
from dataclasses import replace
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_host_authority as authority_module
from sentinel.adaptive import launch_transport as transport
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.store import LifecycleStore, authenticated_query
from tests import test_adaptive_experiment_host_authority as authority_fixtures
from tests import test_adaptive_experiment_host_transport as child_fixtures
from tests import test_adaptive_launch_transport as launch_fixtures
from tests.test_adaptive_ipc import Clock


class ExperimentLaunchDispatchTests(unittest.TestCase):
    serve = launch_fixtures.LaunchTransportTests.serve

    def setUp(self):
        self.fixture = authority_fixtures.ExperimentHostAuthorityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.admit()
        # A production guardian opens an already initialized isolated ledger;
        # retain that exact store in the real factory authority and owner.
        self.fixture.store = LifecycleStore(self.fixture.store.db_path,
            policy_provider=self.fixture.fixture.policy, existing_path=True)
        self.authority, self.binding = self.fixture.guardian()
        self.job = self.fixture.publish_job()
        self.fixture.register_isolated_job(self.authority, self.job)
        self.snapshot = self.fixture.snapshot
        self.context_value = self.fixture.context
        self.coordinator = self.fixture.fixture.coordinator
        self.clock = Clock()
        clock = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.endpoint = NativePipeEndpoint(self.snapshot.logon_id, launch_fixtures.INSTANCE,
                                          self.fixture.guardian_identity)
        self.owner = GuardianLaunchOwner(self.fixture.store, None,
            guardian_epoch=launch_fixtures.EPOCH, authority=self.authority,
            guardian=self.fixture.guardian_process,
            job_factory=lambda *args, **kwargs: self.fail("dispatch fixture attempted native Create"))
        self.service = transport.LaunchService(self.coordinator.db_path, self.endpoint, self.owner)
        self.events = []
        # Fixed bodies are dispatch spies, not an alternative production
        # factory or a wire-selectable authority/permission override.
        replacements = {
            "prepare_experiment_job_intent": self.publication,
            "prepare_execution": self.dispatch,
            "claim_launch": self.dispatch,
            "bind_root": self.dispatch,
            "retire_before_start": self.dispatch,
        }
        for name, callback in replacements.items():
            replacement = patch.object(self.owner, name, side_effect=callback)
            replacement.start()
            self.addCleanup(replacement.stop)

    def request(self, operation="PrepareExecution"):
        request = launch_fixtures.LaunchTransportTests.request(self, operation)
        if type(request) is not transport.PrepareExecutionRequest:
            request = replace(request, job_nonce=self.job.creation_nonce)
        return request

    def result_for(self, request):
        return replace(launch_fixtures.LaunchTransportTests.result_for(self, request),
                       job_name=self.job.job_name, job_nonce=self.job.creation_nonce)

    def assert_unlocked(self):
        self.assertFalse(self.fixture.host.fixture.fixture.policy.active)
        self.assertFalse(self.fixture.fixture.policy.active)
        self.assertIsNone(self.authority._active)
        self.assertEqual(self.fixture.fixture.daily_transactions, [])

    def publication(self, request, peer, *, auth_record, deadline):
        self.assert_unlocked()
        self.assertTrue(self.owner._lock._is_owned())
        self.assertTrue(self.connection.peer_held)
        self.assertEqual(request.operation, "PrepareExecution")
        self.assertIs(peer, self.connection.retained)
        authenticated_query(self.coordinator.db_path, request.execution_id, auth_record)
        self.events.append("publication")

    def dispatch(self, request, peer, *, auth_record, deadline):
        self.assertTrue(self.connection.peer_held)
        self.assertIs(peer, self.connection.retained)
        self.assertGreater(deadline.remaining_ms(), 0)
        authenticated_query(self.coordinator.db_path, request.execution_id, auth_record)
        if type(request) in {transport.CancelBeforeStartRequest, transport.StartFailedRequest}:
            self.assert_unlocked()
        else:
            self.assertTrue(self.owner._lock._is_owned())
            expected = {"PrepareExecution": "prepare", "ClaimLaunch": "claim", "BindRoot": "bind"}
            self.assertEqual(self.authority._active.operation, expected[request.operation])
            self.assertEqual(self.authority._active.execution_id, request.execution_id)
            self.assertFalse(self.fixture.fixture.policy.active)
            self.assertTrue(self.fixture.host.fixture.fixture.policy.active)
            with self.fixture.isolated_policy():
                row = self.fixture.store.query(request.execution_id, existing_path=True)
                self.authority.assert_ready()
                if type(request) is transport.BindRootRequest:
                    self.authority.assert_existing_covered(row)
                else:
                    self.authority.assert_covered(row)
        self.events.append(request.operation)
        return self.result_for(request)

    def connection_for(self, request=None, **kwargs):
        connection = launch_fixtures.LaunchTransportTests.service_connection(self, request, **kwargs)
        process = VerifiedProcess(child_fixtures.Backend(connection.retained.identity), 41,
                                  connection.retained.identity)
        connection.retained = process
        self.addCleanup(process.close)
        original_write = connection.on_write
        def write(connection, outgoing):
            self.assert_unlocked()
            self.assertFalse(self.owner._lock._is_owned())
            self.events.append(outgoing["kind"])
            original_write(connection, outgoing)
        def read(connection, size):
            self.assert_unlocked()
            self.assertFalse(self.owner._lock._is_owned())
        connection.on_write, connection.on_read = write, read
        return connection

    def test_prepare_claim_bind_scope_exits_before_response_and_receipt_io(self):
        for operation in ("PrepareExecution", "ClaimLaunch", "BindRoot"):
            with self.subTest(operation=operation):
                self.events.clear()
                result = self.serve(self.connection_for(self.request(operation)))
                self.assertTrue(result["receipt_verified"])
                expected = ["LaunchChallenge"]
                if operation == "PrepareExecution":
                    expected.append("publication")
                self.assertEqual(self.events, expected + [operation, "LaunchResult"])
                self.assert_unlocked()

    def test_invalid_proof_never_publishes_or_enters_daily_authority(self):
        with patch.object(self.owner, "experiment_launch_scope",
                          side_effect=AssertionError("unverified request entered authority")):
            with self.assertRaisesRegex(IpcError, "launch_auth_failed"):
                self.serve(self.connection_for(proof_transform=lambda proof, challenge:
                    proof | {"mac": "0" * 64}))
        self.assertEqual(self.events, ["LaunchChallenge"])
        self.assert_unlocked()

    def test_dead_original_parent_denies_claim_before_owner_mutation(self):
        self.binding._peer._backend.status = IdentityStatus.DEAD
        with self.assertRaises(authority_module.ExperimentHostAuthorityError):
            self.serve(self.connection_for(self.request("ClaimLaunch")))
        self.assertEqual(self.events, ["LaunchChallenge"])
        self.assert_unlocked()
        self.assertEqual(len(self.fixture.fixture.rows("reservations")), 1)

    def test_publication_failure_cannot_acquire_daily_scope_or_dispatch(self):
        failure = OSError("fixture_publication_ack_unknown")
        with patch.object(self.owner, "prepare_experiment_job_intent", side_effect=failure), \
                patch.object(self.authority, "new_work_scope",
                             side_effect=AssertionError("unpublished Job entered daily scope")):
            with self.assertRaises(OSError) as caught:
                self.serve(self.connection_for())
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.events, ["LaunchChallenge"])
        self.assert_unlocked()

    def test_owner_failure_is_retained_by_original_scope_without_result(self):
        failure = RuntimeError("fixture_owner_outcome_unknown")
        with patch.object(self.owner, "claim_launch", side_effect=failure):
            with self.assertRaises(authority_module.ExperimentHostAuthorityError) as caught:
                self.serve(self.connection_for(self.request("ClaimLaunch")))
        self.assertIs(caught.exception.original_error, failure)
        self.assertIs(self.authority._body_attempt["error"], failure)
        self.assertFalse(self.authority._body_attempt["returned"])
        self.assertEqual(self.events, ["LaunchChallenge"])
        self.assertEqual(len(self.fixture.fixture.rows("reservations")), 1)

    def test_existing_bind_survives_dead_parent_without_new_work_authority(self):
        self.binding._peer._backend.status = IdentityStatus.DEAD
        self.fixture.host.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with patch.object(self.authority, "new_work_scope",
                          side_effect=AssertionError("Bind requested new work authority")):
            self.serve(self.connection_for(self.request("BindRoot")))
        self.assertEqual(self.events, ["LaunchChallenge", "BindRoot", "LaunchResult"])
        self.assertEqual(len(self.fixture.fixture.rows("reservations")), 1)

    def test_cancel_and_failed_start_do_not_enter_daily_authority(self):
        self.binding._peer._backend.status = IdentityStatus.DEAD
        with patch.object(self.owner, "experiment_launch_scope",
                          side_effect=AssertionError("retirement requested daily authority")):
            for operation in ("CancelBeforeStart", "StartFailed"):
                with self.subTest(operation=operation):
                    self.events.clear()
                    self.serve(self.connection_for(self.request(operation)))
                    self.assertEqual(self.events, ["LaunchChallenge", operation, "LaunchResult"])

    def test_scope_release_unknown_retains_original_authority_and_suppresses_result(self):
        provider = self.fixture.host.fixture.fixture.policy
        original = provider.hold
        @contextmanager
        def unknown_release(binding, *, timeout_ms=250):
            with original(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise OSError("fixture_daily_release_unknown")
        with patch.object(provider, "hold", unknown_release):
            with self.assertRaises(authority_module.ExperimentHostAuthorityError) as caught:
                self.serve(self.connection_for(self.request("ClaimLaunch")))
        self.assertIs(caught.exception.experiment_host_authority, self.authority)
        self.assertEqual(str(caught.exception.original_error), "fixture_daily_release_unknown")
        self.assertIsNotNone(self.authority._guard)
        self.assertFalse(self.authority._guard._native_exit_confirmed)
        self.assertEqual(self.events, ["LaunchChallenge", "ClaimLaunch"])
        self.assertEqual(len(self.fixture.fixture.rows("reservations")), 1)

    def test_shallow_copy_cannot_replace_original_guardian_authority(self):
        copied = object.__new__(authority_module.ExperimentBackedHostAuthority)
        copied.__dict__.update(self.authority.__dict__)
        self.owner.authority = copied
        with self.assertRaises((authority_module.ExperimentHostAuthorityError, RuntimeError)):
            self.serve(self.connection_for(self.request("ClaimLaunch")))
        self.assertEqual(self.events, ["LaunchChallenge"])
        self.assert_unlocked()
