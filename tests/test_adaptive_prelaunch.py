"""L1 prelaunch service tests. Synthetic evidence proves no Windows behavior."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import sqlite3
import threading
import unittest
from tests.fixtures.adaptive_evidence import FixturePolicyProvider, fixture_evidence_provider
from unittest.mock import patch

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore, migrate_schema
from tests import test_adaptive_lifecycle as fixtures


class PrelaunchVerifier(fixtures.SyntheticVerifier):
    def __init__(self):
        super().__init__()
        self.overrides = {}

    def __call__(self, operation, row, caller):
        if operation not in {"cancel", "start_failed"}:
            return super().__call__(operation, row, caller)
        self.operations.append(operation)
        proof = LifecycleEvidence(
            operation, row["execution_id"], row["state_revision"], "prelaunch-fixture", caller,
            guardian_epoch=row["guardian_epoch"], job_name=row["job_name"],
            active_process_count=0 if row["job_name"] else None,
            process_ids=() if row["job_name"] else None,
            launch_sealed=True, user_code_started=False, launch_failed=True,
            parent_membership=True,
        )
        return replace(proof, **self.overrides)


class AdaptivePrelaunchTests(unittest.TestCase):
    # Reuse only fixture helpers, without inheriting/re-running another suite.
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.verifier = PrelaunchVerifier()
        self.store.evidence_provider = fixture_evidence_provider(self.verifier)

    def prepared(self, spec=None):
        spec, registered = self.registered(spec)
        row = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        return spec, registered, row

    def claimed(self, spec=None):
        spec, registered, row = self.prepared(spec)
        return spec, registered, self.claim(spec, registered, row["state_revision"])

    def claim(self, spec, registered, revision):
        return self.store.claim_launch(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=revision, claim_token=registered["claim_token"],
            spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")

    def cancel(self, spec, revision, **kwargs):
        return self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=revision, now=fixtures.NOW + 1, **kwargs)

    def fail(self, spec, revision, **kwargs):
        return self.store.mark_start_failed(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=revision, now=fixtures.NOW + 1, **kwargs)

    def allocation(self, spec):
        table = "reservations" if spec.reservation.kind is AllocationKind.DIRECT else "worker_reservations"
        row = self.connection().execute(f"SELECT * FROM {table} WHERE id=?", (spec.reservation.id,)).fetchone()
        return dict(row) if row else None

    def archive(self, spec):
        table = "executions" if spec.reservation.kind is AllocationKind.DIRECT else "routed_executions"
        return self.connection().execute(f"SELECT outcome FROM {table} WHERE reservation_id=?", (spec.reservation.id,)).fetchall()

    def test_reserved_cancel_releases_only_exact_direct_or_routed_allocation(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                spec, registered = self.registered(self.spec(kind=kind))
                other, _ = self.registered(self.spec(kind=kind))
                unchanged = self.allocation(other)
                done = self.cancel(spec, 0)
                self.assertTrue(done["cancelled"])
                self.assertEqual(done["state"], "CANCELLED_BEFORE_START")
                self.assertEqual(done["cancel_requested_at"], fixtures.NOW + 1)
                self.assertEqual(done["launch_sealed"], 1)
                self.assertEqual(done["claim_consumed"], 1)
                self.assertEqual(done["launch_in_flight"], 0)
                self.assertIsNone(self.allocation(spec))
                self.assertEqual(self.allocation(other), unchanged)
                self.assertEqual([r[0] for r in self.archive(spec)], ["managed_cancelled_before_start"])
                retry = LifecycleStore(self.db).cancel_before_start(spec.execution_id,
                    caller=fixtures.WRAPPER, expected_revision=done["state_revision"])
                self.assertEqual(retry["state_revision"], done["state_revision"])
                self.assertEqual(len(self.archive(spec)), 1)
                self.assertIsNone(self.store.prepare_registration(spec, caller=fixtures.WRAPPER,
                    now=fixtures.NOW + 2)["claim_token"])
                self.assertEqual(self.connection().execute(
                    "SELECT claim_token_hash FROM managed_executions WHERE execution_id=?",
                    (spec.execution_id,)).fetchone()[0], "")

    def test_prepared_cancel_seals_and_prevents_reusing_original_claim(self):
        spec, registered, prepared = self.prepared()
        done = self.cancel(spec, prepared["state_revision"])
        with self.assertRaisesRegex(LifecycleError, "claim_binding_mismatch"):
            self.claim(spec, registered, done["state_revision"])
        self.assertIsNone(self.allocation(spec))

    def test_prepared_empty_without_seal_or_never_started_evidence_retains_capacity(self):
        spec, _, row = self.prepared()
        before = self.allocation(spec)
        for fields in ({"launch_sealed": False}, {"user_code_started": None},
                       {"user_code_started": True}, {"active_process_count": None},
                       {"active_process_count": 1}, {"process_ids": None},
                       {"process_ids": (fixtures.ROOT.pid,)}, {"root": fixtures.ROOT}):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
                    self.cancel(spec, row["state_revision"])
                self.assertEqual(self.allocation(spec), before)
                self.assertEqual(self.store.query(spec.execution_id), row)

    def test_reserved_record_cannot_use_an_invented_empty_job(self):
        spec, _ = self.registered()
        for fields in ({"job_name": "other-job"}, {"active_process_count": 0, "process_ids": ()},
                       {"guardian_epoch": "other-epoch"}):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
                    self.cancel(spec, 0)
        self.assertIsNotNone(self.allocation(spec))

    def test_prepared_cancel_rejects_wrong_job_epoch_and_current_runtime_epoch(self):
        spec, _, row = self.prepared()
        for fields in ({"job_name": "other-job"}, {"guardian_epoch": "other-epoch"}):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
                    self.cancel(spec, row["state_revision"])
        self.verifier.overrides = {}
        self.connection().execute("UPDATE adaptive_runtime SET guardian_epoch='new-guardian'")
        with self.assertRaisesRegex(LifecycleError, "guardian_identity_mismatch"):
            self.cancel(spec, row["state_revision"])
        self.assertIsNotNone(self.allocation(spec))

    def test_exact_caller_and_revision_checked_before_native_verifier(self):
        spec, registered, row = self.prepared()
        self.verifier.operations.clear()
        for method in (self.store.cancel_before_start, self.store.mark_start_failed):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
                    method(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                for caller in (replace(fixtures.WRAPPER, pid=999),
                               replace(fixtures.WRAPPER, created_filetime_100ns=fixtures.WRAPPER.created_filetime_100ns + 1),
                               replace(fixtures.WRAPPER, logon_id="different-logon")):
                    with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
                        method(spec.execution_id, caller=caller, expected_revision=row["state_revision"])
        self.assertEqual(self.verifier.operations, [])
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_default_verifier_and_public_boolean_cannot_cancel_or_certify_failure(self):
        spec, _, row = self.prepared()
        default = LifecycleStore(self.db)
        for method in (default.cancel_before_start, default.mark_start_failed):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(LifecycleError, "native_lifecycle_evidence_unavailable"):
                    method(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"])
                with self.assertRaises(TypeError):
                    method(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=row["state_revision"],
                        user_code_started=False)
        self.assertIsNotNone(self.allocation(spec))

    def test_post_claim_cancel_is_durable_pending_and_preserves_all_capacity(self):
        spec, registered, row = self.claimed()
        allocation = self.allocation(spec)
        # Empty is not a release signal after ClaimLaunch.
        result = self.cancel(spec, row["state_revision"])
        self.assertFalse(result["cancelled"])
        self.assertEqual(result["reason"], "cancel_pending_reconciliation")
        self.assertEqual(result["state"], "LAUNCHING")
        self.assertEqual(result["launch_in_flight"], 1)
        self.assertEqual(result["claim_consumed"], 1)
        self.assertEqual(result["launch_sealed"], 0)
        self.assertEqual(result["heartbeat_at"], row["heartbeat_at"])
        self.assertEqual(result["floor_commit_bytes"], row["floor_commit_bytes"])
        self.assertEqual(self.allocation(spec), allocation)
        self.assertEqual(len(self.archive(spec)), 0)
        again = self.cancel(spec, result["state_revision"])
        self.assertEqual(again["state_revision"], result["state_revision"])
        self.assertEqual(again["cancel_requested_at"], result["cancel_requested_at"])
        self.assertFalse(self.claim(spec, registered, result["state_revision"])["launch_authorized"])

    def test_running_root_exit_and_ttl_hold_do_not_make_cancel_release(self):
        spec, row = self.running()
        row = self.store.mark_root_exited(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=row["state_revision"], exit_code=7)
        allocation = self.allocation(spec)
        pending = self.cancel(spec, row["state_revision"])
        self.assertEqual(pending["state"], "DRAINING")
        self.assertEqual(pending["root_outcome"], "7")
        held = self.store.hold(spec.execution_id, expected_revision=pending["state_revision"], reason="reservation_expired")
        again = self.cancel(spec, held["state_revision"])
        self.assertEqual(again["state"], "UNCERTAIN_HOLD")
        self.assertEqual(again["root_outcome"], "7")
        self.assertEqual(self.allocation(spec), allocation)
        with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
            self.fail(spec, again["state_revision"])

    def test_cancel_and_claim_race_never_releases_authorized_work(self):
        for attempt in range(8):
            with self.subTest(attempt=attempt):
                spec, registered, prepared = self.prepared()
                start = threading.Barrier(2)
                verifier = self.verifier
                def rendezvous(operation, row, caller):
                    proof = verifier(operation, row, caller)
                    if operation in {"claim", "cancel"}:
                        start.wait(timeout=5)
                    return proof
                contender = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(rendezvous),
                                           policy_provider=FixturePolicyProvider(fixtures.WRAPPER.logon_id))
                def invoke(operation):
                    try:
                        if operation == "claim":
                            return contender.claim_launch(spec.execution_id, caller=fixtures.WRAPPER,
                                expected_revision=prepared["state_revision"], claim_token=registered["claim_token"],
                                spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
                        return contender.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                            expected_revision=prepared["state_revision"], now=fixtures.NOW + 1)
                    except LifecycleError as error:
                        return {"error": str(error)}
                with ThreadPoolExecutor(max_workers=2) as pool:
                    claimed, cancelled = list(pool.map(invoke, ("claim", "cancel")))
                final = self.store.query(spec.execution_id)
                if claimed.get("launch_authorized"):
                    self.assertEqual(final["state"], "LAUNCHING")
                    self.assertEqual(cancelled.get("error"), "revision_conflict")
                    self.assertIsNotNone(self.allocation(spec))
                    self.assertEqual(len(self.archive(spec)), 0)
                else:
                    self.assertTrue(cancelled.get("cancelled"))
                    self.assertIn(claimed.get("error"), {"revision_conflict", "claim_binding_mismatch"})
                    self.assertEqual(final["state"], "CANCELLED_BEFORE_START")
                    self.assertIsNone(self.allocation(spec))
                    self.assertEqual(len(self.archive(spec)), 1)

    def test_proven_launch_failure_archives_direct_and_routed_once(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                spec, registered, row = self.claimed(self.spec(kind=kind))
                done = self.fail(spec, row["state_revision"])
                self.assertEqual(done["state"], "START_FAILED")
                self.assertEqual(done["launch_in_flight"], 0)
                self.assertEqual(done["launch_sealed"], 1)
                self.assertEqual(done["claim_consumed"], 1)
                self.assertIsNone(done["root_outcome"])
                self.assertIsNone(self.allocation(spec))
                self.assertEqual([r[0] for r in self.archive(spec)], ["managed_start_failed"])
                retry = LifecycleStore(self.db).mark_start_failed(spec.execution_id, caller=fixtures.WRAPPER,
                    expected_revision=done["state_revision"])
                self.assertEqual(retry, done)
                self.assertEqual(len(self.archive(spec)), 1)
                with self.assertRaisesRegex(LifecycleError, "claim_binding_mismatch"):
                    self.claim(spec, registered, done["state_revision"])

    def test_preclaim_failure_closes_attempt_without_authorizing_launch(self):
        for prepare in (False, True):
            with self.subTest(prepare=prepare):
                spec, _ = self.registered()
                row = self.store.query(spec.execution_id)
                if prepare:
                    row = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                done = self.fail(spec, row["state_revision"])
                self.assertEqual(done["state"], "START_FAILED")
                self.assertIsNone(self.allocation(spec))

    def test_held_preclaim_attempt_requires_positive_failure_to_reconcile(self):
        for prepare in (False, True):
            with self.subTest(prepare=prepare):
                spec, _ = self.registered()
                row = self.store.query(spec.execution_id)
                if prepare:
                    row = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                held = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="heartbeat_lost")
                pending = self.cancel(spec, held["state_revision"])
                self.assertEqual(pending["reason"], "cancel_pending_reconciliation")
                self.assertIsNotNone(self.allocation(spec))
                done = self.fail(spec, pending["state_revision"])
                self.assertEqual(done["state"], "START_FAILED")
                self.assertIsNone(self.allocation(spec))

    def test_false_or_unknown_failure_proof_preserves_inflight_and_floor(self):
        spec, _, row = self.claimed()
        row = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="launch_ack_lost")
        allocation = self.allocation(spec)
        for fields, error in (({"launch_failed": False}, "launch_failure_unverified"),
                              ({"launch_failed": None}, "launch_failure_unverified"),
                              ({"user_code_started": None}, "never_started_unverified"),
                              ({"user_code_started": True}, "never_started_unverified"),
                              ({"launch_sealed": False}, "never_started_unverified"),
                              ({"root": fixtures.ROOT}, "never_started_unverified"),
                              ({"active_process_count": 1}, "never_started_unverified")):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                with self.assertRaisesRegex(LifecycleError, error):
                    self.fail(spec, row["state_revision"])
                self.assertEqual(self.store.query(spec.execution_id), row)
                self.assertEqual(self.allocation(spec), allocation)

    def test_start_unknown_positive_failure_clears_hold_and_retains_cancel_audit(self):
        spec, _, row = self.claimed()
        row = self.cancel(spec, row["state_revision"])
        row = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="launch_ack_lost")
        self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        done = self.fail(spec, row["state_revision"])
        self.assertEqual(done["state"], "START_FAILED")
        self.assertIsNone(done["hold_reason"])
        self.assertEqual(done["cancel_requested_at"], fixtures.NOW + 1)
        self.assertEqual(self.connection().execute("SELECT admission_barrier FROM adaptive_runtime").fetchone()[0], "RECOVERY_HOLD")
        self.assertIsNone(self.allocation(spec))

    def test_failure_cannot_close_running_or_root_bound_hold(self):
        spec, row = self.running()
        with self.assertRaisesRegex(LifecycleError, "invalid_lifecycle_transition"):
            self.fail(spec, row["state_revision"])
        held = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="heartbeat_lost")
        with self.assertRaisesRegex(LifecycleError, "never_started_unverified"):
            self.fail(spec, held["state_revision"])
        self.assertIsNotNone(self.allocation(spec))

    def test_nested_cancel_and_failure_leave_parent_and_sibling_capacity_intact(self):
        parent, parent_row = self.running()
        parent_allocation = self.allocation(parent)
        sibling, _ = self.registered(self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id))
        sibling_row = self.store.query(sibling.execution_id)
        for operation in (self.cancel, self.fail):
            with self.subTest(operation=operation.__name__):
                child, _ = self.registered(self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id))
                done = operation(child, 0)
                self.assertIn(done["state"], {"CANCELLED_BEFORE_START", "START_FAILED"})
                self.assertIsNone(done["job_name"])
                self.assertIsNone(done["reservation_id"])
                self.assertEqual(self.store.query(parent.execution_id), parent_row)
                self.assertEqual(self.store.query(sibling.execution_id), sibling_row)
                self.assertEqual(self.allocation(parent), parent_allocation)
                self.assertEqual(len(self.archive(parent)), 0)

    def test_nested_cancel_requires_positive_child_never_started_and_membership(self):
        parent, _ = self.running()
        child, _ = self.registered(self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id))
        for fields, error in (({"parent_membership": False}, "parent_membership_unverified"),
                              ({"user_code_started": None}, "never_started_unverified"),
                              ({"active_process_count": 1, "process_ids": (fixtures.ROOT.pid,)}, "never_started_unverified")):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                with self.assertRaisesRegex(LifecycleError, error):
                    self.cancel(child, 0)
        self.assertEqual(self.store.query(child.execution_id)["state"], "RESERVED")
        self.assertIsNotNone(self.allocation(parent))

    def test_unreconciled_descendant_blocks_prelaunch_release(self):
        parent, _ = self.running()
        child, _ = self.registered(self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id))
        # Fault injection: an impossible stale state must not orphan its child.
        self.connection().execute("""UPDATE managed_executions SET state='PREPARED',
            claim_consumed=0,launch_in_flight=0,launch_sealed=0,root_pid=NULL,
            root_created_filetime_100ns=NULL WHERE execution_id=?""", (parent.execution_id,))
        row = self.store.query(parent.execution_id)
        for method in (self.cancel, self.fail):
            with self.subTest(method=method.__name__):
                with self.assertRaisesRegex(LifecycleError, "live_descendants_unreconciled"):
                    method(parent, row["state_revision"])
        self.assertIsNotNone(self.allocation(parent))
        self.assertEqual(self.store.query(child.execution_id)["state"], "RESERVED")

    def test_failure_proof_loses_to_revision_change_without_releasing(self):
        spec, _, row = self.claimed()
        verifier = self.verifier
        def change_revision(operation, record, caller):
            proof = verifier(operation, record, caller)
            if operation == "start_failed":
                self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="launch_ack_lost")
            return proof
        self.store.evidence_provider = fixture_evidence_provider(change_revision)
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.fail(spec, row["state_revision"])
        self.assertEqual(self.store.query(spec.execution_id)["state"], "START_UNKNOWN")
        self.assertIsNotNone(self.allocation(spec))

    def test_archive_failure_rolls_back_cancel_seal_token_and_allocation(self):
        spec, _ = self.registered()
        row = self.store.query(spec.execution_id)
        allocation = self.allocation(spec)
        conn = self.connection()
        conn.execute("CREATE TRIGGER reject_archive BEFORE INSERT ON executions BEGIN SELECT RAISE(ABORT, 'fixture'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.cancel(spec, 0)
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertEqual(self.allocation(spec), allocation)
        self.assertEqual(conn.execute("SELECT length(claim_token_hash) FROM managed_executions").fetchone()[0], 64)

    def test_missing_allocation_binding_cannot_terminalize_or_archive_another_row(self):
        spec, _ = self.registered()
        row = self.store.query(spec.execution_id)
        self.connection().execute("UPDATE reservations SET lifecycle_managed=0 WHERE id=?", (spec.reservation.id,))
        with self.assertRaisesRegex(LifecycleError, "allocation_binding_missing"):
            self.cancel(spec, 0)
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertIsNotNone(self.allocation(spec))
        self.assertEqual(len(self.archive(spec)), 0)

    def test_cancel_and_failure_evidence_must_bind_operation_execution_and_revision(self):
        spec, _, row = self.prepared()
        for fields in ({"operation": "finalize"}, {"execution_id": "different-execution"},
                       {"state_revision": row["state_revision"] + 1}, {"caller": fixtures.ROOT}):
            with self.subTest(fields=fields):
                self.verifier.overrides = fields
                for method in (self.cancel, self.fail):
                    with self.assertRaisesRegex(LifecycleError, "invalid_lifecycle_evidence"):
                        method(spec, row["state_revision"])
        self.assertIsNotNone(self.allocation(spec))

    def test_new_evidence_tristates_reject_truthy_strings_and_integers(self):
        spec, _ = self.registered()
        proof = self.verifier("cancel", self.store.query(spec.execution_id), fixtures.WRAPPER)
        for field in ("user_code_started", "launch_failed"):
            for value in ("false", 0, 1, [], {}):
                with self.subTest(field=field, value=value):
                    with self.assertRaisesRegex(ValueError, "invalid_evidence_boolean"):
                        replace(proof, **{field: value})

    def test_terminal_replays_require_exact_revision_and_caller(self):
        for operation in (self.store.cancel_before_start, self.store.mark_start_failed):
            with self.subTest(operation=operation.__name__):
                spec, _ = self.registered()
                done = operation(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
                    operation(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
                    operation(spec.execution_id, caller=fixtures.ROOT, expected_revision=done["state_revision"])
                self.assertEqual(len(self.archive(spec)), 1)

    def test_prelaunch_verification_occurs_outside_the_write_transaction(self):
        verifier = self.verifier
        def assert_unlocked(operation, record, caller):
            conn = sqlite3.connect(self.db, timeout=0, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            finally:
                conn.close()
            return verifier(operation, record, caller)
        self.store.evidence_provider = fixture_evidence_provider(assert_unlocked)
        for operation in (self.cancel, self.fail):
            spec, _ = self.registered()
            operation(spec, 0)

    def test_routed_registration_accepts_canonical_local_without_legacy_flag(self):
        store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier), local_host_id="fixture-host")
        spec = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(spec)
        self.connection().execute("UPDATE workers SET capabilities_json=?",
            (json.dumps({"canonical_host_id": "fixture-host"}),))
        row = store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertTrue(row["registered"])
        self.assertEqual(row["allocation_kind"], "routed")
        self.assertEqual(self.allocation(spec)["execution_id"], spec.execution_id)

    def test_routed_registration_rejects_conflicting_or_remote_locality(self):
        store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier), local_host_id="fixture-host")
        spec = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(spec)
        before = self.allocation(spec)
        for capabilities in ({"local": True, "canonical_host_id": "remote-host"},
                             {"local": False, "canonical_host_id": "fixture-host"},
                             {"canonical_host_id": "remote-host"}, {},
                             {"local": "true", "canonical_host_id": "fixture-host"}):
            with self.subTest(capabilities=capabilities):
                self.connection().execute("UPDATE workers SET capabilities_json=?", (json.dumps(capabilities),))
                with self.assertRaisesRegex(LifecycleError, "nonlocal_allocation"):
                    store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
                self.assertEqual(self.allocation(spec), before)

    def test_store_binds_host_once_outside_sql_transactions(self):
        def host_identity():
            conn = sqlite3.connect(self.db, timeout=0, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            finally:
                conn.close()
            return "fixture-host"
        with patch("sentinel.adaptive.store.local_host_identity", side_effect=host_identity) as observe:
            store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier))
            spec = self.spec(kind=AllocationKind.ROUTED)
            self.allocate(spec)
            self.connection().execute("UPDATE workers SET capabilities_json=?",
                (json.dumps({"canonical_host_id": "fixture-host"}),))
            store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
            observe.assert_called_once_with()

    def test_additive_cancel_column_migration_preserves_rows_and_serializes(self):
        spec, _ = self.registered()
        source = self.connection()
        legacy = self.directory / "before-cancel-column.db"
        conn = sqlite3.connect(legacy, isolation_level=None)
        try:
            for table in ("adaptive_runtime", "managed_executions"):
                schema = source.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0]
                conn.execute(schema.replace(", cancel_requested_at REAL", ""))
                columns = [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]
                rows = source.execute(f"SELECT {','.join(columns)} FROM {table}").fetchall()
                conn.executemany(f"INSERT INTO {table} VALUES({','.join('?' for _ in columns)})", rows)
        finally:
            conn.close()
        start = threading.Barrier(2)
        def migrate(_):
            conn = sqlite3.connect(legacy, timeout=3, isolation_level=None)
            try:
                start.wait(timeout=5)
                migrate_schema(conn)
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(migrate, range(2)))
        conn = sqlite3.connect(legacy)
        try:
            self.assertEqual([r[1] for r in conn.execute("PRAGMA table_info(managed_executions)")].count("cancel_requested_at"), 1)
            self.assertEqual(conn.execute("SELECT execution_id,cancel_requested_at FROM managed_executions").fetchone(),
                             (spec.execution_id, None))
            self.assertEqual(conn.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0],
                             source.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0])
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
