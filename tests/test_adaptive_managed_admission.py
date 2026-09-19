"""Atomic managed admission in isolated SQLite; synthetic lifecycle evidence.

These tests exercise real admission transactions, not Job launch or control.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from sentinel.adaptive.admission import ManagedAdmission, ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ResourceDemand
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore
from sentinel.coordinator import Coordinator
from tests.test_adaptive_admission_context import FakeCurrentProcess, PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, NOW, status
from tests.fixtures.adaptive_legacy_admission_31871ae import LegacyAdmissionCoordinator


class ManagedAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        self.process = FakeCurrentProcess()
        override = patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=self.process)
        override.start()
        self.addCleanup(override.stop)
        cpu = patch("os.cpu_count", return_value=12)
        cpu.start()
        self.addCleanup(cpu.stop)

    def context(self, **kwargs):
        context = ManagedAdmission.current(**(PAYLOAD | kwargs))
        self.addCleanup(context.close)
        return context

    def conn(self):
        conn = sqlite3.connect(self.coordinator.db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def admit(self, context, state=None, *, now=NOW, config=None):
        return self.coordinator.admit_managed(context, state or status(now=now), now=now,
                                              config=CONFIG if config is None else config)

    def counts(self):
        conn = self.conn()
        return tuple(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                     for table in ("queue", "reservations", "managed_executions"))

    def test_one_admission_atomically_binds_exact_identity_resources_and_hashes(self):
        context = self.context()
        snapshot = context.snapshot()
        result = self.admit(context)
        self.assertTrue(result["allowed"])
        self.assertFalse(result["launch_authorized"])
        self.assertEqual(result["state"], "RESERVED")
        self.assertEqual(self.counts(), (0, 1, 1))
        conn = self.conn()
        allocation = conn.execute("SELECT * FROM reservations").fetchone()
        row = conn.execute("SELECT * FROM managed_executions").fetchone()
        self.assertEqual((allocation["execution_id"], row["reservation_id"]),
                         (snapshot.execution_id, result["reservation_id"]))
        self.assertEqual(allocation["spec_hash"], snapshot.request.spec_hash)
        self.assertEqual(allocation["managed_spec_hash"], snapshot.spec_hash)
        self.assertEqual(row["spec_hash"], snapshot.spec_hash)
        self.assertEqual(row["admission_binding_hash"], snapshot.binding_hash)
        self.assertEqual(row["claim_token_hash"], hashlib.sha256(context.launch_claim_token().encode("ascii")).hexdigest())
        self.assertEqual(row["wrapper_created_filetime_100ns"], str(snapshot.wrapper_identity.created_filetime_100ns))
        self.assertEqual(row["wrapper_pid"], os.getpid())
        for key, value in snapshot.requested.to_dict().items():
            self.assertEqual(row["floor_" + key], value)
        self.assertEqual(row["logon_id"], snapshot.logon_id)

    def test_failure_between_inserts_rolls_back_queue_allocation_and_lifecycle(self):
        context = self.context()
        self.conn().execute("""CREATE TRIGGER fail_binding BEFORE INSERT ON managed_executions
                             BEGIN SELECT RAISE(ABORT,'injected binding failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected binding failure"):
            self.admit(context)
        self.assertEqual(self.counts(), (0, 0, 0))
        self.conn().execute("DROP TRIGGER fail_binding")
        retry = self.admit(context)
        self.assertEqual(retry["reason"], "managed_request_missing")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_lost_ack_reuses_same_allocation_and_original_claim_without_renewal(self):
        context = self.context()
        token = context.launch_claim_token()
        with patch.object(self.coordinator, "_mirror", side_effect=OSError("injected lost reply")):
            with self.assertRaises(OSError):
                self.admit(context)
        before = dict(self.conn().execute("SELECT * FROM reservations").fetchone())
        result = self.admit(context, now=NOW + 1)
        self.assertTrue(result["allowed"])
        self.assertTrue(result["reused"])
        self.assertFalse(result["launch_authorized"])
        self.assertEqual(result["reservation_id"], before["id"])
        self.assertEqual(before, dict(self.conn().execute("SELECT * FROM reservations").fetchone()))
        self.assertEqual(token, context.launch_claim_token())
        self.assertNotIn(token, json.dumps(result))
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_original_context_token_reaches_existing_one_use_launch_claim(self):
        context = self.context()
        result = self.admit(context)
        snapshot = context.snapshot()
        def verifier(operation, row, caller):
            return LifecycleEvidence(operation, row["execution_id"], row["state_revision"], "synthetic", caller,
                guardian_epoch="synthetic-guardian", job_name="Local\\ResourceSentinel.Test.synthetic",
                original_cpu_disabled=True, durable_manifest=True, legacy_exclusion=True,
                active_process_count=0, process_ids=())
        store = LifecycleStore(self.coordinator.db_path, verifier=verifier)
        prepared = store.mark_prepared(result["execution_id"], caller=snapshot.wrapper_identity, expected_revision=0)
        args = dict(caller=snapshot.wrapper_identity, claim_token=context.launch_claim_token(),
                    spec_hash=snapshot.spec_hash, guardian_epoch="synthetic-guardian",
                    expected_revision=prepared["state_revision"])
        claimed = store.claim_launch(result["execution_id"], **args)
        self.assertTrue(claimed["launch_authorized"])
        replay = store.claim_launch(result["execution_id"], **args)
        self.assertFalse(replay["launch_authorized"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_concurrent_submissions_have_only_one_allocation(self):
        context = self.context()
        start = Barrier(2)
        def run(_):
            start.wait()
            return self.admit(context)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, range(2)))
        # A repeat can reach SQLite before the first transaction; it may deny,
        # but must not insert a competing attempt. A later exact retry succeeds.
        self.assertEqual(sum(bool(r.get("allowed") and not r.get("reused")) for r in results), 1)
        replay = self.admit(context)
        self.assertTrue(replay["allowed"])
        self.assertTrue(replay["reused"])
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_queued_intent_obeys_capacity_and_retries_same_attempt(self):
        context = self.context()
        blocked = self.admit(context, status(commit=94))
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["reason"], "commit_capacity")
        self.assertEqual(self.counts(), (1, 0, 0))
        row = dict(self.conn().execute("SELECT * FROM queue").fetchone())
        self.assertEqual(row["managed_execution_id"], context.snapshot().execution_id)
        self.assertTrue(row["spec_hash"].startswith("managed-v1:"))
        self.assertNotEqual(row["spec_hash"], context.snapshot().request.spec_hash)
        allowed = self.admit(context, now=NOW + 1)
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["request_key"], blocked["request_key"])
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_managed_queue_cannot_be_promoted_by_legacy_retry_or_admit(self):
        context = self.context()
        result = self.admit(context, status(commit=94))
        retried = self.coordinator.retry_queued(result["request_key"], status(), config=CONFIG, now=NOW)
        self.assertEqual(retried["reason"], "managed_request_requires_context")
        direct = self.coordinator.admit(context.snapshot().request, status(), config=CONFIG, now=NOW)
        self.assertEqual(direct["reason"], "managed_request_requires_context")
        self.assertEqual(self.counts(), (1, 0, 0))

    def test_prechange_retry_algorithm_rejects_managed_hash_discriminator(self):
        context = self.context()
        result = self.admit(context, status(commit=94))
        before = dict(self.conn().execute("SELECT * FROM queue").fetchone())
        legacy = LegacyAdmissionCoordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        denied = legacy.retry_queued(result["request_key"], status(), config=CONFIG, now=NOW)
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reason"], "request_spec_mismatch")
        self.assertEqual(before, dict(self.conn().execute("SELECT * FROM queue").fetchone()))
        self.assertEqual(self.counts(), (1, 0, 0))

    def test_prechange_retry_cannot_create_legacy_capacity_after_queue_disappears(self):
        for expired in (False, True):
            with self.subTest(expired=expired):
                context = self.context()
                snapshot = context.snapshot()
                result = self.admit(context, status(commit=94))
                legacy = LegacyAdmissionCoordinator(self.directory,
                    pid_identity=lambda pid: (True, snapshot.request.owner_started))
                if not expired:
                    observe = legacy._cleanup_observations
                    def cancel_after_read():
                        observations = observe()
                        self.conn().execute("DELETE FROM queue WHERE request_key=?", (result["request_key"],))
                        return observations
                    legacy._cleanup_observations = cancel_after_read
                now = NOW + 1900 if expired else NOW
                with self.assertRaisesRegex(sqlite3.IntegrityError, "managed_admission_context_required"):
                    legacy.retry_queued(result["request_key"], status(now=now), config=CONFIG, now=now)
                self.assertEqual(self.counts()[1:], (0, 0))
                # The expired deletion was in the aborted old transaction. The
                # current implementation expires it without retrying a launch.
                replay = self.admit(context, now=now)
                self.assertEqual(replay["reason"], "managed_request_missing")
                self.assertEqual(self.counts(), (0, 0, 0))

    def test_managed_guard_precedes_legacy_fuzzy_handoff(self):
        context = self.context()
        snapshot = context.snapshot()
        legacy = replace(snapshot.request, tool_use_id="")
        old = self.coordinator.admit(legacy, status(), config=CONFIG, now=NOW)
        self.assertTrue(old["allowed"])
        self.admit(context, status(commit=94))
        denied = self.coordinator.admit(snapshot.request, status(), config=CONFIG, now=NOW)
        self.assertEqual(denied["reason"], "managed_request_requires_context")
        self.assertEqual(self.counts(), (1, 1, 0))

    def test_prechange_fuzzy_handoff_cannot_upgrade_after_queue_removal(self):
        context = self.context()
        snapshot = context.snapshot()
        old = self.coordinator.admit(replace(snapshot.request, tool_use_id=""), status(), config=CONFIG, now=NOW)
        self.assertTrue(old["allowed"])
        self.admit(context, status(commit=94))
        self.coordinator.cancel_queued(owner_pid=os.getpid(), request_key=snapshot.request.request_key)
        before = dict(self.conn().execute("SELECT * FROM reservations").fetchone())
        legacy = LegacyAdmissionCoordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        for entry in (legacy, self.coordinator):
            with self.subTest(algorithm=type(entry).__name__):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "managed_admission_context_required"):
                    entry.admit(snapshot.request, status(), config=CONFIG, now=NOW)
                self.assertEqual(before, dict(self.conn().execute("SELECT * FROM reservations").fetchone()))
                self.assertEqual(self.counts(), (0, 1, 0))

    def test_legacy_exact_reservation_or_queue_cannot_upgrade(self):
        for queued in (False, True):
            with self.subTest(queued=queued):
                context = self.context()
                snapshot = context.snapshot()
                if queued:
                    self.coordinator.admit(snapshot.request, status(commit=94), config=CONFIG, now=NOW)
                else:
                    # A pre-existing/corrupt exact-key legacy row is not an
                    # adoption credential. New legacy INSERTs in the managed
                    # namespace are now also rejected by a database trigger.
                    old = self.coordinator.admit(replace(snapshot.request, tool_use_id="legacy:" + snapshot.execution_id),
                                                 status(), config=CONFIG, now=NOW)
                    self.conn().execute("UPDATE reservations SET request_key=? WHERE id=?", (snapshot.request.request_key, old["reservation_id"]))
                result = self.admit(context)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reason"], "request_spec_mismatch" if queued else "legacy_reservation_cannot_be_adopted")
                self.assertEqual(self.conn().execute("SELECT count(*) FROM managed_executions").fetchone()[0], 0)

    def test_same_text_is_two_distinct_attempts_and_shared_principal(self):
        first, second = self.context(requested=ResourceDemand(.5, 1 << 29, 1 << 29, 0)), self.context(requested=ResourceDemand(.5, 1 << 29, 1 << 29, 0))
        a, b = self.admit(first), self.admit(second)
        self.assertTrue(a["allowed"] and b["allowed"])
        self.assertNotEqual(a["reservation_id"], b["reservation_id"])
        self.assertNotEqual(a["request_key"], b["request_key"])
        self.assertEqual(first.snapshot().principal_id, second.snapshot().principal_id)
        self.assertEqual(self.counts(), (0, 2, 2))

    def test_removed_or_expired_queue_does_not_resurrect_same_attempt(self):
        for expiry in (False, True):
            with self.subTest(expiry=expiry):
                context = self.context()
                result = self.admit(context, status(commit=94))
                if not expiry:
                    self.coordinator.cancel_queued(owner_pid=os.getpid(), request_key=result["request_key"])
                retried = self.admit(context, now=NOW + 1900 if expiry else NOW + 1)
                self.assertEqual(retried["reason"], "managed_request_missing")
                self.assertEqual(self.counts(), (0, 0, 0))

    def test_corrupt_queued_metadata_is_rejected_not_silently_repaired(self):
        context = self.context()
        self.admit(context, status(commit=94))
        self.conn().execute("UPDATE queue SET cpu_units=cpu_units+1")
        result = self.admit(context)
        self.assertEqual(result["reason"], "request_spec_mismatch")
        self.assertEqual(self.counts(), (1, 0, 0))

    def test_corrupt_registered_binding_or_hash_cannot_replay(self):
        for column, value in (("principal_id", "other-principal"), ("claim_token_hash", "a" * 64),
                              ("wrapper_created_filetime_100ns", "123"), ("spec_hash", "b" * 64)):
            with self.subTest(column=column):
                context = self.context(requested=ResourceDemand(.5, 1 << 29, 1 << 29, 0))
                result = self.admit(context)
                self.assertTrue(result["allowed"])
                self.conn().execute(f"UPDATE managed_executions SET {column}=? WHERE execution_id=?", (value, result["execution_id"]))
                with self.assertRaisesRegex(LifecycleError, "managed_admission_binding_mismatch"):
                    self.admit(context)

    def test_legacy_release_and_ttl_cannot_drop_managed_capacity(self):
        context = self.context()
        result = self.admit(context, config=CONFIG | {"reservation_ttl_min": 1})
        self.assertEqual(self.coordinator.release(owner_pid=os.getpid(), now=NOW + 1), 0)
        held = self.admit(context, now=NOW + 121)
        self.assertEqual(held["reason"], "managed_execution_held")
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertEqual(held["reservation_id"], result["reservation_id"])

    def test_retained_floor_still_blocks_other_work_after_grace_and_owner_loss(self):
        context = self.context(requested=ResourceDemand(.5, 4 << 30, 4 << 30, 0))
        result = self.admit(context)
        self.assertTrue(result["allowed"])
        self.coordinator.pid_identity = lambda pid: (False, 0.0)
        other = self.context(requested=ResourceDemand(.5, 1 << 30, 1 << 30, 0))
        denied = self.admit(other, status(now=NOW + 121, used_ram=54), now=NOW + 121)
        self.assertFalse(denied["allowed"])
        self.assertIn(denied["reason"], {"ram_capacity", "ram_safety"})
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_managed_hash_cannot_fall_back_to_legacy_hash_when_binding_is_damaged(self):
        context = self.context()
        result = self.admit(context)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "managed_admission_context_required"):
            self.conn().execute("UPDATE reservations SET managed_spec_hash=NULL WHERE id=?", (result["reservation_id"],))
        self.assertTrue(self.admit(context)["allowed"])
        self.conn().execute("UPDATE reservations SET managed_spec_hash=? WHERE id=?", ("c" * 64, result["reservation_id"]))
        with self.assertRaisesRegex(LifecycleError, "allocation_spec_mismatch"):
            self.admit(context)

    def test_terminal_replay_never_reserves_again(self):
        context = self.context()
        result = self.admit(context)
        def verifier(operation, row, caller):
            return LifecycleEvidence(operation, row["execution_id"], row["state_revision"], "synthetic", caller,
                                     launch_sealed=True, user_code_started=False)
        store = LifecycleStore(self.coordinator.db_path, verifier=verifier)
        done = store.cancel_before_start(result["execution_id"], caller=context.snapshot().wrapper_identity,
                                         expected_revision=0, now=NOW + 1)
        self.assertEqual(done["state"], "CANCELLED_BEFORE_START")
        replay = self.admit(context, now=NOW + 2)
        self.assertEqual(replay["reason"], "managed_execution_terminal")
        self.assertFalse(replay["launch_authorized"])
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_public_entry_requires_retained_context_not_claimed_json_or_snapshot(self):
        context = self.context()
        for item in (context.snapshot(), context.snapshot().wrapper_identity, {"owner_pid": os.getpid()}, None):
            with self.subTest(item=type(item).__name__), self.assertRaises(TypeError):
                self.admit(item)
        context.close()
        with self.assertRaises(ManagedAdmissionUnavailable):
            self.admit(context)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_unknown_native_identity_cannot_enter_transaction(self):
        context = self.context()
        self.process.observed = IdentityObservation(self.process.identity, IdentityStatus.UNKNOWN, "test_unknown")
        with patch.object(self.coordinator, "_db", side_effect=AssertionError("transaction entered")):
            with self.assertRaises(ManagedAdmissionUnavailable):
                self.admit(context)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_native_observation_occurs_outside_writer_transaction(self):
        context = self.context()
        original = self.process.observe
        def observe():
            conn = sqlite3.connect(self.coordinator.db_path, timeout=0, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            finally:
                conn.close()
            return original()
        self.process.observe = observe
        self.assertTrue(self.admit(context)["allowed"])

    def test_raw_payload_cwd_and_claim_never_reach_db_or_mirrors(self):
        context = self.context()
        token = context.launch_claim_token()
        self.admit(context, status(commit=94))
        self.admit(context)
        needles = [b"private-launch-marker", b"private-cwd-marker", token.encode("ascii")]
        for path in self.directory.iterdir():
            if path.is_file():
                data = path.read_bytes()
                for needle in needles:
                    self.assertNotIn(needle, data, path.name)
        self.assertEqual(self.conn().execute("SELECT command_text FROM reservations").fetchone()[0], "")

    def test_policy_mismatch_or_stale_measurements_never_create_capacity(self):
        for cfg in (CONFIG | {"admission_policy": "legacy"}, CONFIG | {"local_allocatable_ram_gib": 60},
                    CONFIG | {"local_commit_headroom_gib": 3}, CONFIG | {"local_physical_headroom_gib": 3}):
            with self.subTest(config=cfg):
                result = self.admit(self.context(), config=cfg)
                self.assertEqual(result["reason"], "managed_policy_mismatch")
                self.assertEqual(self.counts(), (0, 0, 0))
        result = self.admit(self.context(), status(now=NOW - 301))
        self.assertFalse(result["allowed"])
        self.assertEqual(self.counts(), (1, 0, 0))


@unittest.skipUnless(os.name == "nt", "native current-wrapper admission requires Windows")
class NativeManagedAdmissionSmokeTests(unittest.TestCase):
    def test_native_context_reaches_isolated_atomic_admission_without_launch(self):
        # Capacity/status are deterministic fixtures; the process identity is
        # truly native. The outer test runner has normal real-host admission.
        with tempfile.TemporaryDirectory() as directory:
            coordinator = Coordinator(directory, pid_identity=lambda pid: (None, 0.0))
            with ManagedAdmission.current(**PAYLOAD) as context:
                result = coordinator.admit_managed(context, status(), config=CONFIG, now=NOW)
                self.assertTrue(result["allowed"])
                self.assertFalse(result["launch_authorized"])
                row = LifecycleStore(coordinator.db_path).query(result["execution_id"])
                self.assertEqual(row["wrapper_pid"], os.getpid())
                self.assertEqual(row["wrapper_created_filetime_100ns"],
                                 str(context.snapshot().wrapper_identity.created_filetime_100ns))
                self.assertRegex(row["logon_id"], r"^S-1-5-5-[0-9]+-[0-9]+$")
                self.assertIsNone(row["job_name"])
                self.assertEqual(row["state"], "RESERVED")


if __name__ == "__main__":
    unittest.main()
