"""Original authenticated witness pins; existing native freshness is preserved."""
import copy
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.pipe_windows import NativeDeadline
from tests import test_adaptive_daily_readiness_lock_boundary as fixtures


class DailyReadinessPinTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.DailyReadinessLockBoundaryTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def check(self, authority):
        authority.revalidate(authority._endpoint, authority._binding)

    def test_same_identity_peer_replacement_is_rejected_without_observation(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            authority = scope.authority
            original = authority._peer
            replacement = VerifiedProcess(original._backend, original._handle, original.identity)
            with patch.object(authority, "_peer", replacement), \
                    patch.object(replacement, "observe", side_effect=AssertionError("replacement observed")), \
                    self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                self.check(authority)
            self.assertIs(authority._original_peer, original)
            self.check(authority)

    def test_changed_native_handle_backend_identity_or_lock_is_rejected(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            peer = scope.authority._peer
            for field, value in (("_handle", peer._handle + 7), ("_backend", object()),
                    ("_identity", copy.copy(peer.identity)), ("_lock", threading.Lock()),
                    ("_close_outcome_unknown", True), ("_handle", None)):
                with self.subTest(field=field), patch.object(peer, field, value), \
                        patch.object(peer, "observe", side_effect=AssertionError("changed peer observed")), \
                        self.assertRaisesRegex(transport.DailyReadinessError, "original_peer_changed"):
                    self.check(scope.authority)
            self.check(scope.authority)

    def test_copied_authority_cannot_observe_or_close_original_peer(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            original = scope.authority
            copied = object.__new__(type(original))
            copied.__dict__.update(original.__dict__)
            before = list(self.fixture.server_backend.closed)
            for operation in (lambda: self.check(copied), copied.close):
                with self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                    operation()
            self.assertEqual(self.fixture.server_backend.closed, before)
            self.check(original)

    def test_changed_deadline_object_or_internal_values_cannot_renew_authority(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            authority = scope.authority
            deadline = authority._deadline
            with patch.object(authority, "_deadline", NativeDeadline.after_ms(1000)), \
                    self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                self.check(authority)
            for field, value in (("_end", deadline._end + 1000), ("_start", deadline._start + 1),
                    ("_pid", deadline._pid + 1), ("_api", object())):
                with self.subTest(field=field), patch.object(deadline, field, value), \
                        self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                    self.check(authority)
            self.check(authority)

    def test_replacing_equal_binding_or_mutating_payload_is_rejected(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            authority = scope.authority
            with patch.object(authority, "_binding", dict(authority._binding)), \
                    self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                self.check(authority)
            with patch.dict(authority._binding, config_digest="f" * 64), \
                    self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                self.check(authority)
            self.check(authority)

    def test_endpoint_mutation_is_rejected_even_when_caller_holds_same_object(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            endpoint = scope.authority._endpoint
            original = endpoint.instance_id
            try:
                object.__setattr__(endpoint, "instance_id", "00000000-0000-4000-8000-000000000001")
                with self.assertRaisesRegex(transport.DailyReadinessError, "original_authority_changed"):
                    self.check(scope.authority)
            finally:
                object.__setattr__(endpoint, "instance_id", original)

    def test_mutation_during_observation_is_rejected_after_native_return(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            peer = scope.authority._peer
            original = peer._handle
            def changed_observe():
                result = VerifiedProcess.observe(peer)
                peer._handle = original + 1
                return result
            try:
                with patch.object(peer, "observe", side_effect=changed_observe), \
                        self.assertRaisesRegex(transport.DailyReadinessError, "original_peer_changed"):
                    self.check(scope.authority)
            finally:
                peer._handle = original

    def test_original_native_death_and_deadline_expiry_still_fail(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            self.fixture.server_backend.status = IdentityStatus.DEAD
            with self.assertRaisesRegex(transport.DailyReadinessError, "original_peer_unavailable"):
                self.check(scope.authority)
            self.fixture.server_backend.status = IdentityStatus.ALIVE
            self.fixture.clock.now += 1000
            with self.assertRaisesRegex(Exception, "pipe_timeout"):
                self.check(scope.authority)

    def test_positive_close_is_idempotent_and_disables_revalidation(self):
        with generation.readiness_scope(self.fixture.db) as scope:
            authority = scope.authority
        before = list(self.fixture.server_backend.closed)
        authority.close()
        self.assertEqual(self.fixture.server_backend.closed, before)
        with self.assertRaisesRegex(transport.DailyReadinessError, "authority_unavailable"):
            self.check(authority)


if __name__ == "__main__":
    unittest.main()
