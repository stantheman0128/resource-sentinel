"""Portable pre-create ledger tests with explicit synthetic native providers.

These tests create only temporary SQLite databases. They prove ordering and
failure semantics, not Windows capability, host admission or collector handoff.
The real S1 owner must separately retain its native identity and creation fence.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
import sqlite3
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.policy import PolicyError, PolicyGuard
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore
from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease
from tests import test_adaptive_lifecycle as fixtures


class ScopePolicy:
    """Faultable L1 lease, never a native mutex or host permission."""
    def __init__(self):
        self.store = None
        self.active = False
        self.abandoned = False
        self.enter_error = None
        self.exit_error = None
        self.enter_guard = self.exit_guard = "not_called"
        self.entries = 0

    def current_logon(self):
        return fixtures.WRAPPER.logon_id

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        self.entries += 1
        self.enter_guard = self.store._policy.current_guard()
        if self.enter_error:
            raise self.enter_error
        self.active = True
        try:
            yield PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, self.abandoned)
        finally:
            # Native release can partly succeed: no borrower may depend on
            # this scope once its body has ended, even during cleanup callbacks.
            self.exit_guard = self.store._policy.current_guard()
            self.active = False
            if self.exit_error:
                raise self.exit_error


class AdaptiveJobScopeTests(unittest.TestCase):
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.policy = ScopePolicy()
        self.store = LifecycleStore(self.db, policy_provider=self.policy, evidence_provider=self.evidence)
        self.policy.store = self.store
        self.scopes = {}
        self.creation = {}
        self.transform = lambda proof: proof
        self.cleanup_error = None
        self.events = []

    @contextmanager
    def evidence(self, operation, row, caller):
        if operation == "register":
            yield self.verifier(operation, row, caller)
            return
        name, nonce, epoch = self.scopes[row["execution_id"]]
        never = self.creation[row["execution_id"]] == "never"
        if operation == "register_scope":
            self.assertTrue(self.policy.active)
            self.assertIsNotNone(self.store._policy.assert_held())
            # The provider must be entered outside any SQLite writer lock.
            with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            self.events.append("scope_proof_before_commit")
        proof = LifecycleEvidence(operation, row["execution_id"], row["state_revision"],
            "synthetic-native-scope", caller, guardian_epoch=epoch, job_name=name,
            active_process_count=None if never else 0, process_ids=None if never else (),
            launch_sealed=operation != "register_scope", user_code_started=False,
            original_cpu_disabled=not never, durable_manifest=operation != "register_scope",
            legacy_exclusion=operation != "register_scope", current_cpu_disabled=not never,
            recovery_manifest_settled=operation != "register_scope", job_nonce=nonce,
            job_creation_never_attempted=never)
        try:
            yield self.transform(proof)
        finally:
            if operation == "register_scope":
                self.assertTrue(self.policy.active)
                self.assertIsNotNone(self.store._policy.assert_held())
                self.events.append("scope_proof_cleanup")
            if self.cleanup_error:
                raise self.cleanup_error

    @contextmanager
    def held(self):
        guard = self.store._policy.prepare(fixtures.WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            yield guard

    def scope_arguments(self, spec, *, production=False):
        nonce = uuid4().hex
        name = (f"Local\\ResourceSentinel.Job.{spec.execution_id}.{nonce}" if production else
                f"Local\\ResourceSentinel.Test.Job.{nonce}")
        self.scopes[spec.execution_id] = (name, nonce, "fixture-guardian")
        self.creation[spec.execution_id] = "never"
        return dict(caller=fixtures.WRAPPER, expected_revision=0, guardian_epoch="fixture-guardian",
                    job_name=name, job_nonce=nonce)

    def scoped(self, spec=None):
        spec, registered = self.registered(spec)
        args = self.scope_arguments(spec)
        with self.held():
            row = self.store.register_job_scope(spec.execution_id, **args)
        return spec, registered, row

    def allocation(self, spec):
        return dict(self.connection().execute("SELECT * FROM reservations WHERE id=?", (spec.reservation.id,)).fetchone())

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def test_scope_is_durable_before_create_without_second_allocation_or_containment(self):
        spec, _ = self.registered()
        allocation = self.allocation(spec)
        args = self.scope_arguments(spec, production=True)
        with self.held() as guard:
            row = self.store.register_job_scope(spec.execution_id, **args)
            self.assertIs(self.store._policy.current_guard(), guard)
            persisted = self.store.query(spec.execution_id)
            self.assertEqual(persisted, row)
            self.assertEqual((row["state"], row["coverage"], row["state_revision"]), ("RESERVED", "unmanaged", 1))
            self.assertEqual((row["job_name"], row["job_nonce"], row["guardian_epoch"]),
                             (args["job_name"], args["job_nonce"], args["guardian_epoch"]))
            self.assertEqual((row["claim_consumed"], row["launch_in_flight"]), (0, 0))
            self.assertNotIn("launch_authorized", row)
            self.assertEqual(self.allocation(spec), allocation)
            self.assertEqual(self.connection().execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
        self.assertEqual(self.events, ["scope_proof_before_commit", "scope_proof_cleanup"])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_no_current_policy_or_fabricated_guard_can_register(self):
        spec, _ = self.registered()
        args = self.scope_arguments(spec)
        with self.assertRaisesRegex(LifecycleError, "policy_scope_not_held"):
            self.store.register_job_scope(spec.execution_id, **args)
        with self.held() as guard:
            forged = PolicyGuard(guard.binding, guard.nonce)
            with self.assertRaisesRegex(PolicyError, "policy_scope_not_held"):
                self.store._policy.assert_held(forged)
        self.assertIsNone(self.store.query(spec.execution_id)["job_name"])

    def test_default_native_evidence_remains_unavailable_even_with_policy_held(self):
        spec, _ = self.registered()
        args = self.scope_arguments(spec)
        provider = ScopePolicy()
        unavailable = LifecycleStore(self.db, policy_provider=provider)
        provider.store = unavailable
        guard = unavailable._policy.prepare(fixtures.WRAPPER.logon_id)
        with unavailable._policy.hold(guard):
            with self.assertRaisesRegex(LifecycleError, "native_lifecycle_evidence_unavailable"):
                unavailable.register_job_scope(spec.execution_id, **args)
        self.assertIsNone(self.store.query(spec.execution_id)["job_name"])

    def test_invalid_name_nonce_and_owner_rejected_without_scope_write(self):
        spec, _ = self.registered()
        args = self.scope_arguments(spec)
        invalid = [dict(job_name="Local\\Unowned.Job." + args["job_nonce"]),
                   dict(job_name=args["job_name"] + "extra"), dict(job_nonce="A" * 32),
                   dict(job_nonce="x"), dict(guardian_epoch="bad\n"),
                   dict(caller=ProcessIdentity(999, fixtures.WRAPPER.created_filetime_100ns, fixtures.WRAPPER.logon_id))]
        with self.held():
            for changed in invalid:
                with self.subTest(changed=tuple(changed)), self.assertRaises(LifecycleError):
                    self.store.register_job_scope(spec.execution_id, **(args | changed))
                self.assertIsNone(self.store.query(spec.execution_id)["job_name"])

    def test_repeat_scope_never_remints_or_implies_retry_create(self):
        spec, _, row = self.scoped()
        name, nonce, epoch = self.scopes[spec.execution_id]
        with self.held():
            with self.assertRaisesRegex(LifecycleError, "job_scope_already_registered"):
                self.store.register_job_scope(spec.execution_id, caller=fixtures.WRAPPER,
                    expected_revision=row["state_revision"], guardian_epoch=epoch, job_name=name, job_nonce=nonce)
        self.assertEqual(self.store.query(spec.execution_id), row)

    def test_registration_requires_matching_identity_and_positive_never_create_fence(self):
        spec, _ = self.registered()
        args = self.scope_arguments(spec)
        allocation = self.allocation(spec)
        with self.held():
            for changed in (dict(job_nonce=uuid4().hex), dict(guardian_epoch="different"),
                            dict(job_creation_never_attempted=False),
                            dict(active_process_count=0, process_ids=()), dict(root=fixtures.ROOT)):
                with self.subTest(changed=tuple(changed)):
                    self.transform = lambda proof, changed=changed: replace(proof, **changed)
                    with self.assertRaisesRegex(LifecycleError, "job_scope_registration_unverified"):
                        self.store.register_job_scope(spec.execution_id, **args)
                    self.assertIsNone(self.store.query(spec.execution_id)["job_name"])
                    self.assertEqual(self.allocation(spec), allocation)

    def test_uncreated_and_uncertain_scopes_count_toward_ten_job_limit(self):
        rows = [self.scoped() for _ in range(10)]
        spec, _, row = rows[0]
        self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="identity_unknown")
        extra, _ = self.registered()
        args = self.scope_arguments(extra)
        with self.held():
            with self.assertRaisesRegex(LifecycleError, "managed_job_limit_reached"):
                self.store.register_job_scope(extra.execution_id, **args)
        self.assertIsNone(self.store.query(extra.execution_id)["job_name"])
        prepared_spec, _, prepared_row = rows[1]
        self.creation[prepared_spec.execution_id] = "created"
        # The already registered tenth slot is not counted twice at preparation.
        prepared = self.store.mark_prepared(prepared_spec.execution_id, caller=fixtures.WRAPPER,
                                            expected_revision=prepared_row["state_revision"])
        self.assertEqual(prepared["state"], "PREPARED")

    def test_named_scope_evidence_cannot_change_nonce_name_or_epoch(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"
        for changed in (dict(job_nonce=uuid4().hex), dict(job_name="Local\\Unowned"), dict(guardian_epoch="different")):
            with self.subTest(changed=tuple(changed)):
                self.transform = lambda proof, changed=changed: replace(proof, **changed)
                with self.assertRaisesRegex(LifecycleError, "job_scope_evidence_mismatch"):
                    self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"])
                self.assertEqual(self.store.query(spec.execution_id), row)
                self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.transform = lambda proof: proof
        prepared = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                            expected_revision=row["state_revision"])
        self.assertEqual(prepared["state"], "PREPARED")

    def test_named_scope_rejection_with_evidence_cleanup_failure_keeps_nonce(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"
        self.transform = lambda proof: replace(proof, job_nonce=uuid4().hex)
        self.cleanup_error = RuntimeError("synthetic_scope_cleanup")
        with self.assertRaisesRegex(LifecycleError, "job_scope_evidence_mismatch") as caught:
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=row["state_revision"])
        self.assertIn("lifecycle_evidence_cleanup_failed", caught.exception.__notes__)
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.store._policy.current_guard())

    def test_provider_error_text_cannot_certify_prepublication_rejection(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"

        class FailingScope:
            def __enter__(self):
                raise LifecycleError("job_scope_evidence_mismatch")

            def __exit__(self, *args):
                raise AssertionError("failed entry has no scope to exit")

        self.store.evidence_provider = lambda *args: FailingScope()
        with self.assertRaisesRegex(LifecycleError, "job_scope_evidence_mismatch"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=row["state_revision"])
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.store._policy.current_guard())

    def test_after_yield_error_cannot_impersonate_evidence_validation(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"
        primary = LifecycleError("job_scope_evidence_mismatch")
        with self.assertRaises(LifecycleError) as caught:
            with self.store._publication_scope(fixtures.WRAPPER) as publication:
                with self.store._evidence_scope("prepare", row, fixtures.WRAPPER,
                                                publication=publication):
                    # No publication transaction has certified a rollback;
                    # matching error text in the yielded body proves nothing.
                    raise primary
        self.assertIs(caught.exception, primary)
        self.assertFalse(publication[0].clean_rejection)
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])

    def test_preparation_cannot_claim_empty_before_native_create_attempt(self):
        spec, _, row = self.scoped()
        with self.assertRaisesRegex(LifecycleError, "job_preparation_unverified"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"])
        self.assertEqual(self.store.query(spec.execution_id), row)

    def test_cleanup_failure_retains_registered_capacity_for_reconciliation(self):
        spec, _ = self.registered()
        before = self.allocation(spec)
        args = self.scope_arguments(spec)
        self.cleanup_error = RuntimeError("synthetic_scope_cleanup")
        with self.assertRaisesRegex(LifecycleError, "lifecycle_evidence_cleanup_failed"):
            with self.held():
                self.store.register_job_scope(spec.execution_id, **args)
        self.assertEqual(self.store.query(spec.execution_id)["job_name"], args["job_name"])
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertEqual(self.allocation(spec), before)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.store._policy.current_guard())

    def test_new_native_nonce_cannot_skip_precreate_registration_via_legacy_shape(self):
        spec, row = self.registered()
        self.scope_arguments(spec)
        self.creation[spec.execution_id] = "created"
        with self.assertRaisesRegex(LifecycleError, "job_scope_not_registered"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"])
        current = self.store.query(spec.execution_id)
        self.assertEqual(current["state"], "RESERVED")
        self.assertIsNone(current["job_name"])
        self.assertIsNone(current["job_nonce"])

    def test_barrier_revision_and_binding_fail_before_registering_any_scope(self):
        spec, _ = self.registered()
        args = self.scope_arguments(spec)
        with self.held():
            with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
                self.store.register_job_scope(spec.execution_id, **(args | {"expected_revision": 1}))
            self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
            with self.assertRaisesRegex(LifecycleError, "launch_barrier_active"):
                self.store.register_job_scope(spec.execution_id, **args)
            self.assertIsNone(self.store.query(spec.execution_id)["job_name"])

    def test_irrevocably_never_created_scope_cancels_without_inventing_native_empty(self):
        spec, _, row = self.scoped()
        result = self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                               expected_revision=row["state_revision"], now=fixtures.NOW + 1)
        self.assertTrue(result["cancelled"])
        self.assertEqual((result["state"], result["claim_consumed"], result["launch_sealed"]),
                         ("CANCELLED_BEFORE_START", 1, 1))
        self.assertIsNone(self.connection().execute("SELECT 1 FROM reservations WHERE id=?", (spec.reservation.id,)).fetchone())
        self.assertEqual(self.connection().execute("SELECT count(*) FROM executions WHERE reservation_id=?", (spec.reservation.id,)).fetchone()[0], 1)

    def test_never_created_cancel_rejects_unsettled_manifest_unsealed_or_fake_counts(self):
        spec, _, row = self.scoped()
        for changed in (dict(recovery_manifest_settled=False), dict(launch_sealed=False),
                        dict(active_process_count=0, process_ids=()), dict(user_code_started=None)):
            with self.subTest(changed=tuple(changed)):
                self.transform = lambda proof, changed=changed: replace(proof, **changed)
                with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
                    self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                                  expected_revision=row["state_revision"], now=fixtures.NOW + 1)
                self.assertEqual(self.store.query(spec.execution_id), row)
                self.assertIsNotNone(self.allocation(spec))

    def test_created_cancel_requires_real_empty_disabled_and_settled_observations(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"
        for changed in (dict(current_cpu_disabled=False), dict(recovery_manifest_settled=False),
                        dict(active_process_count=None, process_ids=None),
                        dict(active_process_count=1, process_ids=(fixtures.ROOT.pid,))):
            with self.subTest(changed=tuple(changed)):
                self.transform = lambda proof, changed=changed: replace(proof, **changed)
                with self.assertRaises(LifecycleError):
                    self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                                  expected_revision=row["state_revision"], now=fixtures.NOW + 1)
                self.assertEqual(self.store.query(spec.execution_id), row)
        self.transform = lambda proof: proof
        result = self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                               expected_revision=row["state_revision"], now=fixtures.NOW + 1)
        self.assertTrue(result["cancelled"])

    def test_prepared_scope_cannot_recover_a_never_attempted_creation_capability(self):
        spec, _, row = self.scoped()
        self.creation[spec.execution_id] = "created"
        prepared = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"])
        self.creation[spec.execution_id] = "never"
        with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
            self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                          expected_revision=prepared["state_revision"], now=fixtures.NOW + 1)
        self.assertEqual(self.store.query(spec.execution_id), prepared)

    def test_policy_borrow_is_thread_and_coordinator_local_and_ends_before_release(self):
        other = LifecycleStore(self.db, policy_provider=ScopePolicy())
        with self.held() as guard:
            self.assertIs(self.store._policy.assert_held(), guard)
            self.assertIsNone(other._policy.current_guard())
            with ThreadPoolExecutor(max_workers=1) as executor:
                self.assertIsNone(executor.submit(self.store._policy.current_guard).result(timeout=2))
            with self.assertRaisesRegex(PolicyError, "policy_scope_nested"):
                with self.store._policy.hold(guard):
                    self.fail("nested ownership")
            self.assertEqual(self.policy.entries, 1)
        self.assertIsNone(self.policy.enter_guard)
        self.assertIsNone(self.policy.exit_guard)
        self.assertIsNone(self.store._policy.current_guard())
        with self.assertRaisesRegex(PolicyError, "policy_scope_not_held"):
            self.store._policy.assert_held(guard)

    def test_abandoned_lease_never_exposes_borrowing_authority(self):
        self.policy.abandoned = True
        with self.assertRaisesRegex(PolicyError, "policy_mutex_abandoned"):
            with self.held():
                self.fail("abandoned ownership exposed")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.policy.exit_guard)
        self.assertIsNone(self.store._policy.current_guard())

    def test_unknown_enter_and_release_errors_leave_no_borrowable_guard(self):
        self.policy.enter_error = NativePolicyMutexError("policy_mutex_wait_failed")
        with self.assertRaises(NativePolicyMutexError):
            with self.held():
                self.fail("unknown ownership exposed")
        self.assertIsNone(self.store._policy.current_guard())
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])

    def test_release_failure_preserves_nonce_without_leaving_stale_access(self):
        self.policy.exit_error = RuntimeError("synthetic_release_failed")
        with self.assertRaisesRegex(RuntimeError, "synthetic_release_failed"):
            with self.held() as guard:
                self.assertIs(self.store._policy.assert_held(guard), guard)
        self.assertIsNone(self.store._policy.current_guard())
        self.assertIsNone(self.policy.exit_guard)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])


if __name__ == "__main__":
    unittest.main()
