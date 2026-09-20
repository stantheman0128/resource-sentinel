"""L1 policy ownership tests; synthetic leases prove no native Job behavior."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4

from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.store import LifecycleError, LifecycleStore, SchemaVersionError
from sentinel.adaptive.windows import NativePolicyMutex, NativePolicyMutexError, PolicyMutexLease
from tests import test_adaptive_lifecycle as fixtures
from tests.fixtures.adaptive_evidence import FixturePolicyProvider, fixture_evidence_provider


class ObservedPolicy:
    """Faultable context model with real independent SQLite writer probes."""
    def __init__(self, test):
        self.test = test
        self.logon_id = fixtures.WRAPPER.logon_id
        self.active = False
        self.holds = 0
        self.abandoned = False
        self.enter_error = None
        self.exit_error = None
        self.on_enter = None
        self.lease_transform = None
        self.suppress = False

    def unlocked(self):
        with closing(sqlite3.connect(self.test.db, timeout=0, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()

    def current_logon(self):
        self.unlocked()
        self.test.events.append("policy.identity")
        return self.logon_id

    def hold(self, binding, *, timeout_ms=250):
        provider = self

        class Scope:
            def __enter__(self):
                provider.unlocked()
                provider.holds += 1
                provider.test.assertEqual(timeout_ms, 250)
                runtime = provider.test.runtime()
                provider.test.assertEqual(runtime["policy_instance_id"], binding.instance_id)
                provider.test.assertEqual(runtime["policy_logon_id"], binding.logon_id)
                provider.test.assertEqual(str(UUID(runtime["policy_entry_nonce"])), runtime["policy_entry_nonce"])
                provider.test.events.append("policy.enter")
                if provider.on_enter is not None:
                    provider.on_enter(binding)
                if provider.enter_error is not None:
                    raise provider.enter_error
                provider.active = True
                lease = PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, provider.abandoned)
                return provider.lease_transform(lease) if provider.lease_transform else lease

            def __exit__(self, kind, error, tb):
                provider.unlocked()
                provider.test.assertIsNotNone(provider.test.runtime()["policy_entry_nonce"])
                provider.test.events.append("policy.exit")
                provider.active = False
                if provider.exit_error is not None:
                    raise provider.exit_error
                return provider.suppress

        return Scope()


class AdaptivePolicyScopeTests(unittest.TestCase):
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.preparation_policy = self.policy
        self.events = []
        self.policy = ObservedPolicy(self)
        self.evidence_active = False
        self.evidence_error = None
        self.evidence_cleanup_error = None
        self.store = LifecycleStore(self.db, evidence_provider=self.evidence,
                                    policy_provider=self.policy)

    @contextmanager
    def evidence(self, operation, row, caller):
        if operation != "claim":
            yield self.verifier(operation, row, caller)
            return
        self.assertTrue(self.policy.active)
        self.policy.unlocked()
        self.events.append("evidence.enter")
        if self.evidence_error is not None:
            raise self.evidence_error
        self.evidence_active = True
        try:
            yield self.verifier(operation, row, caller)
        finally:
            self.assertTrue(self.policy.active)
            self.policy.unlocked()
            self.evidence_active = False
            self.events.append("evidence.exit")
            if self.evidence_cleanup_error is not None:
                raise self.evidence_cleanup_error

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def prepared(self, store=None):
        target = store or self.store
        spec = self.spec()
        self.allocate(spec)
        # Publication now acquires POLICY too. Set up the real persisted binding
        # with an explicit neutral provider; observe/fault only the later claim.
        # Do not erase initialized binding state or reset the observed counters.
        with patch.object(target._policy, "provider", self.preparation_policy):
            registered = target.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
            row = target.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        args = dict(caller=fixtures.WRAPPER, expected_revision=row["state_revision"],
                    claim_token=registered["claim_token"], spec_hash=spec.spec_hash,
                    guardian_epoch="fixture-guardian")
        return spec, args

    def assert_unclaimed(self, spec):
        row = self.store.query(spec.execution_id)
        self.assertEqual((row["state"], row["claim_consumed"], row["launch_in_flight"]), ("PREPARED", 0, 0))
        self.assertIsNotNone(self.connection().execute("SELECT 1 FROM reservations WHERE id=?", (spec.reservation.id,)).fetchone())

    def assert_new_store_still_blocked(self, nonce, spec, args):
        provider = ObservedPolicy(self)
        new_store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier),
                                   policy_provider=provider)
        # This execution was prepared before the uncertain operation. Creating
        # it here would itself need POLICY and never reach the claim under test.
        with self.assertRaisesRegex(LifecycleError, "policy_scope_busy"):
            new_store.claim_launch(spec.execution_id, **args)
        self.assertEqual(provider.holds, 0)
        self.assertEqual(self.runtime()["policy_entry_nonce"], nonce)
        self.assert_unclaimed(spec)

    def test_binding_and_nonce_are_durable_before_wait_and_clear_only_after_release(self):
        spec, args = self.prepared()
        original = self.store._cas

        def observe_cas(conn, execution_id, revision, updates):
            self.assertTrue(self.policy.active)
            self.assertTrue(self.evidence_active)
            self.assertTrue(conn.in_transaction)
            self.events.append("claim.transaction")
            return original(conn, execution_id, revision, updates)

        with patch.object(self.store, "_cas", side_effect=observe_cas):
            result = self.store.claim_launch(spec.execution_id, **args)
        self.assertTrue(result["launch_authorized"])
        self.assertEqual(self.events, ["policy.identity", "policy.enter", "evidence.enter",
                                       "claim.transaction", "evidence.exit", "policy.exit"])
        runtime = self.runtime()
        self.assertEqual(runtime["policy_logon_id"], fixtures.WRAPPER.logon_id)
        self.assertEqual(str(UUID(runtime["policy_instance_id"])), runtime["policy_instance_id"])
        self.assertIsNone(runtime["policy_entry_nonce"])

    def test_constructor_performs_no_native_query_or_mutex_acquisition(self):
        with patch("sentinel.adaptive.policy.NativePolicyProvider.current_logon") as identity, \
             patch("sentinel.adaptive.policy.NativePolicyProvider.hold") as hold:
            LifecycleStore(self.db)
        identity.assert_not_called()
        hold.assert_not_called()

    def test_synthetic_evidence_does_not_implicitly_enable_policy_fixture(self):
        spec, args = self.prepared()
        before = self.runtime()
        default = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier))
        with patch("sentinel.adaptive.policy.NativePolicyProvider.current_logon",
                   side_effect=PolicyError("policy_test_native_unavailable")) as identity:
            with self.assertRaisesRegex(LifecycleError, "policy_test_native_unavailable"):
                default.claim_launch(spec.execution_id, **args)
        identity.assert_called_once()
        self.assertEqual(self.policy.holds, 0)
        self.assertEqual(self.runtime(), before)
        self.assert_unclaimed(spec)

    def test_malformed_partial_or_other_logon_binding_cannot_reach_wait(self):
        spec, args = self.prepared()
        for instance, logon in (("invalid", fixtures.WRAPPER.logon_id),
                                (str(uuid4()), None), (None, fixtures.WRAPPER.logon_id),
                                (str(uuid4()), "S-1-5-5-9-9")):
            with self.subTest(instance=instance, logon=logon):
                self.connection().execute("UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?", (instance, logon))
                with self.assertRaisesRegex(LifecycleError, "policy_(binding_invalid|logon_mismatch)"):
                    self.store.claim_launch(spec.execution_id, **args)
                self.assertEqual(self.policy.holds, 0)
                self.assertIsNone(self.runtime()["policy_entry_nonce"])
                self.assert_unclaimed(spec)

    def test_missing_runtime_row_cannot_reach_wait(self):
        spec, args = self.prepared()
        self.connection().execute("DELETE FROM adaptive_runtime")
        with self.assertRaises(SchemaVersionError):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertEqual(self.policy.holds, 0)

    def test_current_logon_mismatch_cannot_rebind_or_wait(self):
        spec, args = self.prepared()
        before = self.runtime()
        self.policy.logon_id = "S-1-5-5-9-9"
        with self.assertRaisesRegex(LifecycleError, "policy_logon_mismatch"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertEqual(self.policy.holds, 0)
        self.assertEqual(self.runtime(), before)
        self.assert_unclaimed(spec)

    def test_initialized_binding_erasure_cannot_create_another_mutex_identity(self):
        first, args = self.prepared()
        self.assertTrue(self.store.claim_launch(first.execution_id, **args)["launch_authorized"])
        self.assertEqual(self.runtime()["policy_binding_initialized"], 1)
        next_spec, next_args = self.prepared()
        self.connection().execute("UPDATE adaptive_runtime SET policy_instance_id=NULL,policy_logon_id=NULL")
        holds = self.policy.holds
        with self.assertRaisesRegex(LifecycleError, "policy_binding_invalid"):
            self.store.claim_launch(next_spec.execution_id, **next_args)
        self.assertEqual(self.policy.holds, holds)
        runtime = self.runtime()
        self.assertEqual(runtime["policy_binding_initialized"], 1)
        self.assertIsNone(runtime["policy_instance_id"])
        self.assertIsNone(runtime["policy_entry_nonce"])
        self.assert_unclaimed(next_spec)

    def test_populated_binding_with_uninitialized_marker_cannot_publish_or_wait(self):
        # Exercise genuinely uninitialized storage before first publication;
        # never reset a live binding merely to recreate the former fixture.
        initial = self.runtime()
        self.assertEqual(initial["policy_binding_initialized"], 0)
        for field in ("policy_instance_id", "policy_logon_id", "policy_entry_nonce"):
            self.assertIsNone(initial[field])
        spec = self.spec()
        self.allocate(spec)
        self.connection().execute("UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?",
                                  (str(uuid4()), fixtures.WRAPPER.logon_id))
        before = self.runtime()
        allocation = dict(self.connection().execute("SELECT * FROM reservations WHERE id=?",
                                                    (spec.reservation.id,)).fetchone())
        with self.assertRaisesRegex(LifecycleError, "policy_binding_invalid"):
            self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertEqual(self.policy.holds, 0)
        self.assertEqual(self.runtime(), before)
        self.assertIsNone(self.connection().execute("SELECT 1 FROM managed_executions WHERE execution_id=?",
                                                   (spec.execution_id,)).fetchone())
        self.assertEqual(dict(self.connection().execute("SELECT * FROM reservations WHERE id=?",
                                                       (spec.reservation.id,)).fetchone()), allocation)

    def test_missing_binding_marker_column_cannot_reach_wait(self):
        spec, args = self.prepared()
        self.connection().execute("ALTER TABLE adaptive_runtime DROP COLUMN policy_binding_initialized")
        with self.assertRaises((LifecycleError, KeyError, sqlite3.Error)):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertEqual(self.policy.holds, 0)
        self.assert_unclaimed(spec)

    def test_nonce_persistence_failure_prevents_native_wait(self):
        spec, args = self.prepared()
        before = self.runtime()
        self.connection().execute("""CREATE TRIGGER fail_policy_entry BEFORE UPDATE OF policy_entry_nonce ON adaptive_runtime
            WHEN NEW.policy_entry_nonce IS NOT NULL BEGIN SELECT RAISE(ABORT,'fixture prewait failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture prewait failure"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertEqual(self.policy.holds, 0)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.runtime(), before)
        self.assert_unclaimed(spec)

    def test_positive_timeout_clears_own_nonce_and_can_retry_original_claim(self):
        spec, args = self.prepared()
        self.policy.enter_error = NativePolicyMutexError("policy_mutex_timeout")
        with self.assertRaisesRegex(LifecycleError, "policy_mutex_timeout"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)
        self.policy.enter_error = None
        self.assertTrue(self.store.claim_launch(spec.execution_id, **args)["launch_authorized"])

    def test_timeout_with_cleanup_uncertainty_retains_entry(self):
        spec, args = self.prepared()
        error = NativePolicyMutexError("policy_mutex_timeout")
        error.add_note("fixture cleanup uncertainty")
        self.policy.enter_error = error
        with self.assertRaisesRegex(LifecycleError, "policy_mutex_timeout"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)

    def test_untyped_lease_cannot_authorize_claim_or_clear_nonce(self):
        spec, args = self.prepared()
        self.policy.lease_transform = lambda lease: {"name": lease.name}
        with self.assertRaisesRegex(LifecycleError, "invalid_policy_lease"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertNotIn("evidence.enter", self.events)
        self.assert_unclaimed(spec)

    def test_lease_for_another_binding_retains_nonce_after_cleanup(self):
        spec, args = self.prepared()
        self.policy.lease_transform = lambda lease: replace(lease, instance_id=str(uuid4()))
        with self.assertRaisesRegex(LifecycleError, "invalid_policy_lease"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIn("policy.exit", self.events)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)

    def test_release_failure_after_commit_cannot_ack_or_reissue_launch(self):
        spec, args = self.prepared()
        standby, standby_args = self.prepared()
        self.policy.exit_error = NativePolicyMutexError("policy_mutex_release_failed")
        with self.assertRaisesRegex(LifecycleError, "policy_mutex_release_failed"):
            self.store.claim_launch(spec.execution_id, **args)
        nonce = self.runtime()["policy_entry_nonce"]
        self.assertIsNotNone(nonce)
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 1)
        calls = self.policy.holds
        retry = self.store.claim_launch(spec.execution_id, **args)
        self.assertFalse(retry["launch_authorized"])
        self.assertTrue(retry["duplicate"])
        self.assertEqual(self.policy.holds, calls)
        self.assert_new_store_still_blocked(nonce, standby, standby_args)

    def test_handle_close_failure_retains_nonce_despite_completed_release(self):
        spec, args = self.prepared()
        self.policy.exit_error = NativePolicyMutexError("policy_mutex_handle_close_failed")
        with self.assertRaisesRegex(LifecycleError, "policy_mutex_handle_close_failed"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 1)

    def test_claim_transaction_rollback_retains_unknown_entry_and_capacity(self):
        spec, args = self.prepared()
        original = self.store._cas
        failure = RuntimeError("fixture claim write failure")

        def fail_after_cas(*values, **kwargs):
            original(*values, **kwargs)
            raise failure

        with patch.object(self.store, "_cas", side_effect=fail_after_cas):
            with self.assertRaises(RuntimeError) as error:
                self.store.claim_launch(spec.execution_id, **args)
        self.assertIs(error.exception, failure)
        self.assert_unclaimed(spec)
        self.assertEqual(self.events[-2:], ["evidence.exit", "policy.exit"])
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])

    def test_evidence_cleanup_failure_after_commit_keeps_nonce_and_duplicate_read_only(self):
        spec, args = self.prepared()
        self.evidence_cleanup_error = RuntimeError("fixture evidence cleanup failure")
        with self.assertRaisesRegex(LifecycleError, "lifecycle_evidence_cleanup_failed"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 1)
        before = list(self.events)
        self.assertFalse(self.store.claim_launch(spec.execution_id, **args)["launch_authorized"])
        self.assertEqual(self.events, before)

    def test_provider_cannot_impersonate_clean_transaction_rejection_by_error_text(self):
        spec, args = self.prepared()
        self.evidence_error = LifecycleError("revision_conflict")
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)

    def test_binding_changed_inside_provider_cannot_consume_claim(self):
        spec, args = self.prepared()
        changed = str(uuid4())
        self.policy.on_enter = lambda binding: self.connection().execute(
            "UPDATE adaptive_runtime SET policy_instance_id=?", (changed,))
        with self.assertRaisesRegex(LifecycleError, "policy_entry_changed"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertEqual(self.runtime()["policy_instance_id"], changed)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)

    def test_clean_barrier_rejection_releases_policy_and_clears_only_entry(self):
        spec, args = self.prepared()
        self.policy.on_enter = lambda binding: self.connection().execute(
            "UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaisesRegex(LifecycleError, "launch_barrier_active"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assert_unclaimed(spec)

    def test_abandoned_mutex_durably_holds_before_any_lifecycle_evidence(self):
        spec, args = self.prepared()
        before = self.runtime()["registry_revision"]
        self.policy.abandoned = True
        with self.assertRaisesRegex(LifecycleError, "policy_mutex_abandoned"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertNotIn("evidence.enter", self.events)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual(self.runtime()["registry_revision"], before + 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assert_unclaimed(spec)

    def test_abandoned_hold_write_failure_survives_new_store_and_normal_next_acquisition(self):
        spec, args = self.prepared()
        self.policy.abandoned = True
        self.connection().execute("""CREATE TRIGGER fail_recovery_hold BEFORE UPDATE OF admission_barrier ON adaptive_runtime
            WHEN NEW.admission_barrier='RECOVERY_HOLD' BEGIN SELECT RAISE(ABORT,'fixture hold write failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture hold write failure"):
            self.store.claim_launch(spec.execution_id, **args)
        nonce = self.runtime()["policy_entry_nonce"]
        self.assertIsNotNone(nonce)
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assert_unclaimed(spec)
        self.connection().execute("DROP TRIGGER fail_recovery_hold")
        self.assert_new_store_still_blocked(nonce, spec, args)

    def test_nonce_clear_write_failure_is_not_a_success_ack(self):
        spec, args = self.prepared()
        self.connection().execute("""CREATE TRIGGER fail_policy_clear BEFORE UPDATE OF policy_entry_nonce ON adaptive_runtime
            WHEN OLD.policy_entry_nonce IS NOT NULL AND NEW.policy_entry_nonce IS NULL
            BEGIN SELECT RAISE(ABORT,'fixture clear failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture clear failure"):
            self.store.claim_launch(spec.execution_id, **args)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 1)
        self.assertFalse(self.store.claim_launch(spec.execution_id, **args)["launch_authorized"])

    def test_concurrent_duplicate_claims_issue_one_authority_under_fixture_policy(self):
        store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier),
                               policy_provider=FixturePolicyProvider(fixtures.WRAPPER.logon_id))
        spec, args = self.prepared(store)
        barrier = threading.Barrier(2)

        def claim(_):
            barrier.wait(timeout=5)
            return store.claim_launch(spec.execution_id, **args)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual(sum(row["launch_authorized"] for row in results), 1)
        self.assertEqual(sum(row["duplicate"] for row in results), 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_explicit_recovery_writer_uses_same_binding_and_cannot_clear_hold(self):
        revision = self.runtime()["registry_revision"]
        result = self.store.enter_recovery_hold(expected_registry_revision=revision)
        self.assertEqual(result["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual(result["registry_revision"], revision + 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertNotIn("evidence.enter", self.events)
        before = list(self.events)
        self.assertEqual(self.store.enter_recovery_hold(expected_registry_revision=revision), result)
        self.assertEqual(self.events, before)


@unittest.skipUnless(os.name == "nt", "real Windows policy consumer required")
class NativePolicyStoreTests(unittest.TestCase):
    """Real default-provider mutex + isolated ledger, never a Job/control gate."""
    def test_default_provider_persists_recovery_hold_and_releases_native_mutex(self):
        with VerifiedProcess.current() as current:
            observed = current.observe()
            self.assertEqual(observed.status, IdentityStatus.ALIVE)
            self.assertEqual(observed.identity, current.identity)
            logon_id = current.identity.logon_id
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "sentinel.db"
            store = LifecycleStore(database)

            def runtime():
                with closing(sqlite3.connect(database)) as conn:
                    conn.row_factory = sqlite3.Row
                    return dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

            before = runtime()
            self.assertEqual(before["policy_binding_initialized"], 0)
            self.assertIsNone(before["policy_instance_id"])
            self.assertIsNone(before["policy_entry_nonce"])
            result = store.enter_recovery_hold(expected_registry_revision=before["registry_revision"])
            after = runtime()
            self.assertEqual(after["mode"], "off")
            self.assertEqual(after["admission_barrier"], "RECOVERY_HOLD")
            self.assertEqual(after["registry_revision"], before["registry_revision"] + 1)
            self.assertEqual(after["policy_logon_id"], logon_id)
            self.assertEqual(after["policy_binding_initialized"], 1)
            self.assertEqual(str(UUID(after["policy_instance_id"])), after["policy_instance_id"])
            self.assertIsNone(after["policy_entry_nonce"])
            self.assertEqual(store.enter_recovery_hold(expected_registry_revision=before["registry_revision"]), result)
            self.assertEqual(runtime(), after)

            # Recovery-hold replay above is read-only. A different native thread
            # must acquire this exact binding to independently prove release.
            acquired, errors = [], []

            def reacquire():
                try:
                    with NativePolicyMutex(after["policy_logon_id"], after["policy_instance_id"]) as mutex:
                        with mutex.acquire(timeout_ms=250) as lease:
                            self.assertFalse(lease.abandoned)
                    self.assertIsNone(mutex._handle)
                    acquired.append(lease)
                except BaseException as error:
                    errors.append(error)

            worker = threading.Thread(target=reacquire, name="isolated-policy-reacquire", daemon=True)
            worker.start()
            worker.join(timeout=5)
            self.assertFalse(worker.is_alive(), "bounded native policy reacquisition did not finish")
            self.assertEqual(errors, [])
            self.assertEqual(len(acquired), 1)
            self.assertEqual(acquired[0].instance_id, after["policy_instance_id"])
            self.assertEqual(acquired[0].logon_id, after["policy_logon_id"])
            self.assertEqual(runtime(), after)


if __name__ == "__main__":
    unittest.main()
