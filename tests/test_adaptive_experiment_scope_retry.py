"""Original parent retry only after positive readiness cleanup and no entry.

Actual isolated SQLite accounting and readiness scope lifetime are exercised.
Native readiness is an explicit fixture, not a Windows recovery gate.
"""
from contextlib import contextmanager
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_host_scope as scope
from tests import test_adaptive_experiment_host_scope as fixtures


class ProductionScopeReadinessRetryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProductionExperimentScopeTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.owner = self.fixture.prepare()

    def test_clean_preflight_refusal_closes_originals_then_retries_same_parent(self):
        f, owner = self.fixture, self.owner
        failure = generation.DailyGenerationUnavailable("daily_readiness_original_peer_unavailable")
        original_close = generation._ReadinessScope.close
        closed = []
        def close(original):
            result = original_close(original)
            self.assertTrue(original.closed)
            self.assertIsNone(original.error)
            closed.append(original)
            return result
        with patch.object(f.proof, "revalidate_scoped_readiness", side_effect=failure), \
                patch.object(owner._daily_policy, "prepare", wraps=owner._daily_policy.prepare) as prepare, \
                patch.object(generation._ReadinessScope, "close", close):
            with self.assertRaises(generation.DailyGenerationUnavailable) as caught:
                owner.reserve_member(f.claim)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(closed), 2)
        prepare.assert_not_called()
        self.assertIsNone(owner._guard)
        self.assertFalse(owner._guard_unknown)
        self.assertIsNone(owner._scope_cleanup_error)
        self.assertEqual(owner._sql_attempts, [])
        self.assertIs(f.demand._native_preparation, owner)
        self.assertIn(failure, owner._errors)
        before = f.fixture.assert_retained(f.demand)
        registered = owner.registered_scope
        result = owner.reserve_member(f.claim)
        self.assertEqual(result["member_id"], f.claim.member_id)
        self.assertIs(owner.registered_scope, registered)
        self.assertEqual(f.fixture.assert_retained(f.demand), before)

    def test_retry_still_revalidates_fresh_readiness_and_never_uses_failed_proof(self):
        f, owner = self.fixture, self.owner
        failure = generation.DailyGenerationUnavailable("daily_config_changed")
        with patch.object(f.proof, "revalidate_scoped_readiness", side_effect=failure) as proof:
            for _ in range(2):
                with self.assertRaises(generation.DailyGenerationUnavailable):
                    owner.reserve_member(f.claim)
                self.assertIsNone(owner._scope_cleanup_error)
            self.assertEqual(proof.call_count, 2)
        self.assertEqual(f.fixture.rows(fixtures.ledger.MEMBERS_TABLE), [])
        f.fixture.assert_retained(f.demand)

    def test_readiness_cleanup_failure_after_clean_refusal_keeps_both_errors(self):
        f, owner = self.fixture, self.owner
        refused = generation.DailyGenerationUnavailable("daily_config_changed")
        cleanup = OSError("synthetic original readiness close acknowledgement lost")
        original_close = generation._ReadinessScope.close
        first = True
        def close(original):
            nonlocal first
            original_close(original)
            if first:
                first = False
                raise cleanup
        with patch.object(f.proof, "revalidate_scoped_readiness", side_effect=refused), \
                patch.object(generation._ReadinessScope, "close", close):
            with self.assertRaises(OSError) as caught:
                owner.reserve_member(f.claim)
        self.assertIs(caught.exception, cleanup)
        self.assertIs(cleanup.production_scope_body_error, refused)
        self.assertIs(owner._scope_cleanup_error, cleanup)
        self.assertIsNone(owner._guard)
        self.assertFalse(owner._guard_unknown)
        with self.assertRaisesRegex(scope.ProductionScopeError, "operation_custody_unsettled"):
            owner.reserve_member(f.claim)

    def test_unknown_cleanup_in_preflight_is_not_hidden_by_normal_context_exit(self):
        f, owner = self.fixture, self.owner
        failure = OSError("synthetic native query completion unknown")
        failure.io_pending = True
        with patch.object(f.proof, "revalidate_scoped_readiness", side_effect=failure):
            with self.assertRaises(OSError) as caught:
                owner.reserve_member(f.claim)
        self.assertIs(caught.exception, failure)
        self.assertIs(owner._scope_cleanup_error, failure)
        self.assertIsNone(owner._guard)
        self.assertFalse(owner._guard_unknown)
        self.assertTrue(getattr(failure, "_daily_readiness_scopes", ()))
        with self.assertRaisesRegex(scope.ProductionScopeError, "operation_custody_unsettled"):
            owner.reserve_member(f.claim)

    def test_unreturned_readiness_acquisition_has_no_positive_cleanup_receipt(self):
        f, owner = self.fixture, self.owner
        failure = OSError("synthetic acquisition interruption")
        @contextmanager
        def interrupted(*args, **kwargs):
            raise failure
            yield
        with patch.object(f.proof, "readiness_scopes", interrupted):
            with self.assertRaises(OSError):
                owner.reserve_member(f.claim)
        self.assertIs(owner._scope_cleanup_error, failure)
        with self.assertRaisesRegex(scope.ProductionScopeError, "operation_custody_unsettled"):
            owner.reserve_member(f.claim)

    def test_prepare_attempt_uncertainty_is_not_reclassified_as_preflight(self):
        f, owner = self.fixture, self.owner
        failure = OSError("synthetic prepare acknowledgement lost")
        with patch.object(owner._daily_policy, "prepare", side_effect=failure):
            with self.assertRaises(OSError):
                owner.reserve_member(f.claim)
        self.assertIs(owner._scope_cleanup_error, failure)
        self.assertTrue(owner._guard_unknown)
        self.assertIsNone(owner._guard)
        with self.assertRaisesRegex(scope.ProductionScopeError, "operation_custody_unsettled"):
            owner.reserve_member(f.claim)


if __name__ == "__main__":
    unittest.main()
