"""Isolated SQLite control-slot tests; synthetic evidence is not native proof."""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.control_slot import ControlSlotError, clear_finished_locked
from sentinel.adaptive.store import ControlSlotRejected, LifecycleError, LifecycleEvidence, LifecycleStore
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_lifecycle as lifecycle


WRAPPER = lifecycle.WRAPPER
ROOT = lifecycle.ROOT
NOW = lifecycle.NOW
EPOCH = "fixture-guardian"


class SlotVerifier:
    """Operation-aware fixture with an exact registered Job nonce."""

    def __init__(self):
        self.nonces = {}
        self.overrides = {}
        self.operations = []
        self.before_control = None

    def nonce(self, execution_id):
        return self.nonces.setdefault(execution_id, uuid4().hex)

    def __call__(self, operation, row, caller):
        self.operations.append(operation)
        nonce = row.get("job_nonce") or self.nonce(row["execution_id"])
        registered = operation == "register_scope"
        empty = row["state"] in {"RESERVED", "PREPARED"} or operation == "finalize"
        root = (None if empty else ROOT)
        if row.get("root_pid") is not None:
            root = type(ROOT)(row["root_pid"], int(row["root_created_filetime_100ns"]), row["logon_id"])
        proof = LifecycleEvidence(
            operation, row["execution_id"], row["state_revision"], "slot-fixture", caller,
            guardian_epoch=EPOCH,
            job_name=row.get("job_name") or "Local\\ResourceSentinel.Test.Job." + nonce,
            job_nonce=None if operation == "register" else nonce,
            root=None if registered else root,
            active_process_count=None if registered else (0 if empty else 1),
            process_ids=None if registered else (() if empty else (ROOT.pid,)),
            launch_sealed=True, original_cpu_disabled=True,
            durable_manifest=True, legacy_exclusion=True, root_exited=True,
            current_cpu_disabled=True, recovery_manifest_settled=True,
            job_creation_never_attempted=registered,
        )
        if operation in {"control_begin", "control_restore"}:
            if self.before_control is not None:
                self.before_control(operation, row)
            proof = replace(proof, **self.overrides)
        return proof


class ControlSlotTests(unittest.TestCase):
    connection = lifecycle.AdaptiveLifecycleTests.connection
    spec = lifecycle.AdaptiveLifecycleTests.spec
    allocate = lifecycle.AdaptiveLifecycleTests.allocate
    registered = lifecycle.AdaptiveLifecycleTests.registered

    def setUp(self):
        lifecycle.AdaptiveLifecycleTests.setUp(self)
        self.verifier = SlotVerifier()
        self.store.evidence_provider = fixture_evidence_provider(self.verifier)
        self.connection().execute("UPDATE adaptive_runtime SET mode='canary'")

    @contextmanager
    def policy_scope(self, store=None):
        store = self.store if store is None else store
        guard = store._policy.prepare(WRAPPER.logon_id)
        with store._policy.hold(guard):
            yield guard

    def prepared(self, spec=None):
        spec, registration = self.registered(spec)
        nonce = self.verifier.nonce(spec.execution_id)
        with self.policy_scope():
            scoped = self.store.register_job_scope(
                spec.execution_id, caller=WRAPPER, expected_revision=registration["state_revision"],
                job_name="Local\\ResourceSentinel.Test.Job." + nonce,
                job_nonce=nonce, guardian_epoch=EPOCH,
            )
        prepared = self.store.mark_prepared(spec.execution_id, caller=WRAPPER,
                                            expected_revision=scoped["state_revision"])
        return spec, prepared, registration["claim_token"]

    def running(self, spec=None):
        spec, prepared, token = self.prepared(spec)
        claimed = self.store.claim_launch(
            spec.execution_id, caller=WRAPPER, expected_revision=prepared["state_revision"],
            claim_token=token, spec_hash=spec.spec_hash, guardian_epoch=EPOCH,
        )
        running = self.store.bind_root(spec.execution_id, caller=WRAPPER,
                                       expected_revision=claimed["state_revision"])
        return spec, running

    def begin(self, spec, row, *, slot_id=None, exemption_revision=7, **changes):
        arguments = dict(caller=WRAPPER, expected_revision=row["state_revision"],
                         slot_id=slot_id or str(uuid4()), exemption_revision=exemption_revision)
        arguments.update(changes)
        return self.store.begin_control_slot_locked(spec.execution_id, **arguments)

    def release(self, spec, row, slot_id, **changes):
        arguments = dict(caller=WRAPPER, expected_revision=row["state_revision"], slot_id=slot_id)
        arguments.update(changes)
        return self.store.release_control_slot_locked(spec.execution_id, **arguments)

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def slot(self):
        row = self.connection().execute("SELECT * FROM adaptive_control_slot").fetchone()
        return None if row is None else dict(row)

    def custody(self):
        conn = self.connection()
        return {table: [tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in ("adaptive_runtime", "adaptive_control_slot", "managed_executions",
                              "reservations", "worker_reservations", "executions", "routed_executions")}

    @contextmanager
    def transaction_failure(self, failure):
        """Fault actual SQLite ownership after BEGIN, keeping snapshot reads intact."""
        real_connect = sqlite3.connect
        events = []

        class FaultConnection(sqlite3.Connection):
            control_transaction = False

            def execute(self, sql, *args):
                result = super().execute(sql, *args)
                if sql == "BEGIN IMMEDIATE":
                    self.control_transaction = True
                return result

            def commit(self):
                result = super().commit()
                if self.control_transaction and failure == "commit_ack":
                    events.append("commit_ack")
                    raise sqlite3.OperationalError("fixture_commit_ack_lost")
                return result

            def rollback(self):
                if self.control_transaction and failure == "rollback":
                    events.append("rollback")
                    raise RuntimeError("fixture_rollback_failed")
                return super().rollback()

            def close(self):
                # Even the simulated close-error case closes its private fd.
                result = super().close()
                if self.control_transaction and failure == "close":
                    events.append("close")
                    raise RuntimeError("fixture_close_failed")
                return result

        def connect(*args, **kwargs):
            if kwargs.get("timeout") == 5:
                kwargs["factory"] = FaultConnection
            return real_connect(*args, **kwargs)

        with patch("sentinel.adaptive.store.sqlite3.connect", side_effect=connect):
            yield events

    def assert_begin_rejected(self, spec, row, **kwargs):
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.begin(spec, row, **kwargs)
        self.assertEqual(self.custody(), before)

    def assert_release_rejected(self, spec, row, slot_id, **kwargs):
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.release(spec, row, slot_id, **kwargs)
        self.assertEqual(self.custody(), before)

    def test_prepared_empty_probe_acquires_exact_slot_and_barrier_atomically(self):
        spec, row, _ = self.prepared()
        with self.policy_scope() as guard:
            before = self.runtime()
            result = self.begin(spec, row)
            slot = self.slot()
            self.assertEqual(result["slot_state"], "HELD")
            self.assertEqual(result["admission_barrier"], "CONTROLLING")
            self.assertFalse(result["duplicate"])
            self.assertIs(result["control_authorized"], False)
            for field in ("execution_id", "job_name", "job_nonce", "guardian_epoch"):
                self.assertEqual(slot[field], row[field])
            self.assertEqual(slot["slot_id"], result["slot_id"])
            self.assertEqual(slot["exemption_revision"], 7)
            self.assertEqual(slot["policy_instance_id"], guard.binding.instance_id)
            self.assertEqual(slot["policy_logon_id"], guard.binding.logon_id)
            self.assertEqual(slot["owner_pid"], WRAPPER.pid)
            self.assertEqual(str(slot["owner_created_filetime_100ns"]), str(WRAPPER.created_filetime_100ns))
            self.assertEqual(self.runtime()["registry_revision"], before["registry_revision"] + 1)
            self.assertEqual(self.store.query(spec.execution_id), row)

    def test_limited_mode_running_execution_can_take_slot(self):
        spec, row = self.running()
        self.connection().execute("UPDATE adaptive_runtime SET mode='limited'")
        with self.policy_scope():
            self.assertEqual(self.begin(spec, row)["slot_state"], "HELD")

    def test_draining_execution_with_zero_current_membership_can_take_slot(self):
        spec, row = self.running()
        row = self.store.mark_root_exited(spec.execution_id, caller=WRAPPER,
                                         expected_revision=row["state_revision"], exit_code=0)
        self.verifier.overrides = dict(active_process_count=0, process_ids=())
        with self.policy_scope():
            self.assertEqual(self.begin(spec, row)["slot_state"], "HELD")

    def test_locked_methods_reject_missing_policy_scope_without_changes(self):
        spec, row, _ = self.prepared()
        self.assert_begin_rejected(spec, row)
        self.assert_release_rejected(spec, row, str(uuid4()))

    def test_query_requires_policy_and_reads_empty_slot_without_mutation(self):
        self.prepared()
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.query_control_slot_locked()
        self.assertEqual(self.custody(), before)
        with self.policy_scope():
            before = self.custody()
            self.assertIsNone(self.store.query_control_slot_locked())
            self.assertEqual(self.custody(), before)

    def test_query_returns_exact_held_and_restored_records_without_mutation(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            for restored in (False, True):
                if restored:
                    self.release(spec, row, first["slot_id"])
                with self.subTest(restored=restored):
                    before = self.custody()
                    self.assertEqual(self.store.query_control_slot_locked(), self.slot())
                    self.assertEqual(self.custody(), before)

    def test_query_refuses_malformed_missing_or_barrier_inconsistent_registry(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            self.begin(spec, row)
            conn = self.connection()
            for field, invalid in (("schema_version", 99), ("policy_instance_id", str(uuid4())),
                                   ("job_nonce", "oversized" * 100),
                                   ("guardian_epoch", "fixture\0" + "x" * 2048)):
                original = self.slot()[field]
                conn.execute("PRAGMA ignore_check_constraints=ON")
                conn.execute(f"UPDATE adaptive_control_slot SET {field}=?", (invalid,))
                conn.execute("PRAGMA ignore_check_constraints=OFF")
                with self.subTest(field=field):
                    before = self.custody()
                    with self.assertRaises(LifecycleError):
                        self.store.query_control_slot_locked()
                    self.assertEqual(self.custody(), before)
                conn.execute(f"UPDATE adaptive_control_slot SET {field}=?", (original,))
            conn.execute("UPDATE adaptive_runtime SET admission_barrier='NONE'")
            before = self.custody()
            with self.assertRaisesRegex(LifecycleError, "control_slot_barrier_mismatch"):
                self.store.query_control_slot_locked()
            self.assertEqual(self.custody(), before)
            conn.execute("UPDATE adaptive_runtime SET admission_barrier='CONTROLLING'")
            conn.execute("DROP TABLE adaptive_control_slot")
            before = tuple(conn.iterdump())
            with self.assertRaises(LifecycleError):
                self.store.query_control_slot_locked()
            self.assertEqual(tuple(conn.iterdump()), before)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_control_slot'").fetchone())

    def test_another_store_policy_guard_cannot_be_borrowed(self):
        spec, row, _ = self.prepared()
        other = LifecycleStore(self.db, policy_provider=self.policy)
        with self.policy_scope(other):
            self.assert_begin_rejected(spec, row)

    def test_caller_pid_reuse_or_different_logon_cannot_take_slot(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            for caller in (replace(WRAPPER, created_filetime_100ns=WRAPPER.created_filetime_100ns + 1),
                           replace(WRAPPER, logon_id="S-1-5-5-9-9")):
                with self.subTest(caller=caller):
                    self.assert_begin_rejected(spec, row, caller=caller)

    def test_stale_lifecycle_revision_cannot_take_slot(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            self.assert_begin_rejected(spec, row, expected_revision=row["state_revision"] - 1)

    def test_invalid_slot_id_or_exemption_revision_cannot_mutate(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            for changes in (dict(slot_id="invalid"), dict(exemption_revision=-1),
                            dict(exemption_revision=True), dict(exemption_revision="7")):
                with self.subTest(changes=changes):
                    before = self.custody()
                    with self.assertRaises((LifecycleError, ValueError)):
                        self.begin(spec, row, **changes)
                    self.assertEqual(self.custody(), before)

    def test_new_slot_refused_in_off_or_shadow_mode(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            for mode in ("off", "shadow"):
                self.connection().execute("UPDATE adaptive_runtime SET mode=?", (mode,))
                with self.subTest(mode=mode):
                    before = self.custody()
                    with self.assertRaisesRegex(ControlSlotRejected, "control_mode_unavailable"):
                        self.begin(spec, row)
                    self.assertEqual(self.custody(), before)

    def test_rollback_or_connection_cleanup_failure_is_not_confirmed_rejection(self):
        spec, row, _ = self.prepared()
        self.connection().execute("UPDATE adaptive_runtime SET mode='off'")
        with self.policy_scope():
            for failure in ("rollback", "close"):
                with self.subTest(failure=failure):
                    before = self.custody()
                    with self.transaction_failure(failure) as events:
                        with self.assertRaises(LifecycleError) as caught:
                            self.begin(spec, row)
                    self.assertNotIsInstance(caught.exception, ControlSlotRejected)
                    self.assertEqual(events, [failure])
                    self.assertEqual(self.custody(), before)

    def test_evidence_cleanup_failure_is_not_confirmed_rejection(self):
        spec, row, _ = self.prepared()
        self.connection().execute("UPDATE adaptive_runtime SET mode='off'")
        exits = []

        @contextmanager
        def failing_provider(operation, snapshot, caller):
            try:
                yield self.verifier(operation, snapshot, caller)
            finally:
                exits.append(operation)
                raise RuntimeError("fixture_evidence_cleanup_failed")

        with self.policy_scope():
            before = self.custody()
            with patch.object(self.store, "evidence_provider", failing_provider):
                with self.assertRaises(LifecycleError) as caught:
                    self.begin(spec, row)
            self.assertNotIsInstance(caught.exception, ControlSlotRejected)
            self.assertEqual(exits, ["control_begin"])
            self.assertEqual(self.custody(), before)

    def test_lost_commit_ack_is_not_confirmed_rejection_and_replay_is_read_only(self):
        spec, row, _ = self.prepared()
        slot_id = str(uuid4())
        with self.policy_scope():
            with self.transaction_failure("commit_ack") as events:
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    self.begin(spec, row, slot_id=slot_id)
            self.assertNotIsInstance(caught.exception, ControlSlotRejected)
            self.assertEqual(events, ["commit_ack"])
            self.assertEqual(self.slot()["slot_id"], slot_id)
            self.assertEqual(self.slot()["slot_state"], "HELD")
            self.assertEqual(self.runtime()["admission_barrier"], "CONTROLLING")
            before = self.custody()
            replay = self.begin(spec, row, slot_id=slot_id)
            self.assertTrue(replay["duplicate"])
            self.assertIs(replay["control_authorized"], False)
            self.assertEqual(self.custody(), before)

    def test_only_background_p2_or_p3_can_begin_new_control(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            for role, priority in (("protected", "P2"), ("neutral", "P2"),
                                   ("background", "P0"), ("background", "P1")):
                self.connection().execute("UPDATE managed_executions SET role=?,priority=? WHERE execution_id=?",
                                          (role, priority, spec.execution_id))
                with self.subTest(role=role, priority=priority):
                    self.assert_begin_rejected(spec, self.store.query(spec.execution_id))
            self.connection().execute("UPDATE managed_executions SET role='background',priority='P3' WHERE execution_id=?",
                                      (spec.execution_id,))
            self.assertEqual(self.begin(spec, self.store.query(spec.execution_id))["slot_state"], "HELD")

    def test_local_routed_allocation_can_begin(self):
        spec, row = self.running(self.spec(kind=AllocationKind.ROUTED))
        with self.policy_scope():
            self.assertEqual(self.begin(spec, row)["slot_state"], "HELD")

    def test_running_without_job_contained_coverage_cannot_begin(self):
        spec, row = self.running()
        self.connection().execute("UPDATE managed_executions SET coverage='unmanaged' WHERE execution_id=?",
                                  (spec.execution_id,))
        with self.policy_scope():
            self.assert_begin_rejected(spec, self.store.query(spec.execution_id))

    def test_nonlocal_routed_allocation_is_rejected(self):
        spec, row = self.running(self.spec(kind=AllocationKind.ROUTED))
        self.connection().execute("""UPDATE workers SET capabilities_json='{"local":false}',
            writer_protocol=1,writer_revision=writer_revision+1 WHERE id='local-alias'""")
        with self.policy_scope():
            self.assert_begin_rejected(spec, row)

    def test_existing_other_slot_cannot_be_replaced(self):
        first, first_row, _ = self.prepared()
        second, second_row, _ = self.prepared()
        with self.policy_scope():
            self.begin(first, first_row)
            self.assert_begin_rejected(second, second_row)

    def test_exact_begin_duplicate_is_read_only_ack_without_new_authority(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            before = self.custody()
            duplicate = self.begin(spec, row, slot_id=first["slot_id"])
            self.assertTrue(duplicate["duplicate"])
            self.assertIs(duplicate["control_authorized"], False)
            self.assertEqual(duplicate["slot_revision"], first["slot_revision"])
            self.assertEqual(self.custody(), before)

    def test_begin_duplicate_does_not_require_new_control_mode_or_clear_recovery_hold(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.connection().execute("UPDATE adaptive_runtime SET mode='off',admission_barrier='RECOVERY_HOLD'")
            before = self.custody()
            duplicate = self.begin(spec, row, slot_id=first["slot_id"])
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(duplicate["admission_barrier"], "RECOVERY_HOLD")
            self.assertEqual(self.custody(), before)

    def test_duplicate_wrong_slot_or_exemption_revision_is_not_rebound(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.assert_begin_rejected(spec, row, slot_id=str(uuid4()))
            self.assert_begin_rejected(spec, row, slot_id=first["slot_id"], exemption_revision=8)

    def test_duplicate_cannot_repair_an_unexpected_none_barrier(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='NONE'")
            self.assert_begin_rejected(spec, row, slot_id=first["slot_id"])

    def test_global_launching_and_start_unknown_block_even_with_zero_inflight_bit(self):
        victim, row, _ = self.prepared()
        other, _, _ = self.prepared()
        with self.policy_scope():
            for state in ("LAUNCHING", "START_UNKNOWN"):
                self.connection().execute("UPDATE managed_executions SET state=?,launch_in_flight=0 WHERE execution_id=?",
                                          (state, other.execution_id))
                with self.subTest(state=state):
                    self.assert_begin_rejected(victim, row, exemption_revision=999)

    def test_global_inflight_flag_blocks_an_otherwise_running_execution(self):
        victim, row, _ = self.prepared()
        other, _ = self.running()
        self.connection().execute("UPDATE managed_executions SET launch_in_flight=1 WHERE execution_id=?",
                                  (other.execution_id,))
        with self.policy_scope():
            self.assert_begin_rejected(victim, row)

    def test_prepared_probe_requires_empty_job_and_unclaimed_launch(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            self.verifier.overrides = dict(active_process_count=1, process_ids=(ROOT.pid,))
            self.assert_begin_rejected(spec, row)
            self.verifier.overrides = {}
            self.connection().execute("UPDATE managed_executions SET claim_consumed=1 WHERE execution_id=?",
                                      (spec.execution_id,))
            self.assert_begin_rejected(spec, self.store.query(spec.execution_id))

    def test_mismatched_or_incomplete_native_scope_evidence_rejects_before_mutation(self):
        spec, row = self.running()
        cases = (dict(job_nonce="f" * 32), dict(job_name="Local\\ResourceSentinel.Test.Wrong"),
                 dict(guardian_epoch="other-epoch"), dict(durable_manifest=False),
                 dict(legacy_exclusion=False), dict(active_process_count=2),
                 dict(root=replace(ROOT, created_filetime_100ns=ROOT.created_filetime_100ns + 1)))
        with self.policy_scope():
            for changes in cases:
                self.verifier.overrides = changes
                with self.subTest(changes=tuple(changes)):
                    self.assert_begin_rejected(spec, row)

    def test_evidence_is_obtained_outside_sqlite_writer_transaction(self):
        spec, row, _ = self.prepared()
        calls = []

        def probe(operation, _row):
            conn = self.connection()
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
            calls.append(operation)

        self.verifier.before_control = probe
        with self.policy_scope():
            first = self.begin(spec, row)
            self.release(spec, row, first["slot_id"])
        self.assertEqual(calls, ["control_begin", "control_restore"])

    def test_begin_slot_and_barrier_roll_back_together_on_sql_failure(self):
        spec, row, _ = self.prepared()
        self.connection().execute("""CREATE TRIGGER fixture_block_slot BEFORE UPDATE ON adaptive_runtime
            WHEN NEW.admission_barrier='CONTROLLING'
            BEGIN SELECT RAISE(ABORT,'fixture_barrier_failure'); END""")
        with self.policy_scope():
            before = self.custody()
            with self.assertRaises((LifecycleError, sqlite3.DatabaseError)):
                self.begin(spec, row)
            self.assertEqual(self.custody(), before)

    def test_release_rolls_back_slot_and_barrier_together_on_sql_failure(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.connection().execute("""CREATE TRIGGER fixture_block_release BEFORE UPDATE ON adaptive_runtime
                WHEN NEW.admission_barrier='RECOVERY_HOLD'
                BEGIN SELECT RAISE(ABORT,'fixture_recovery_barrier_failure'); END""")
            before = self.custody()
            with self.assertRaises((LifecycleError, sqlite3.DatabaseError)):
                self.release(spec, row, first["slot_id"])
            self.assertEqual(self.custody(), before)

    def test_restore_releases_slot_but_keeps_recovery_barrier_and_allocation(self):
        spec, row = self.running()
        with self.policy_scope():
            first = self.begin(spec, row)
            released = self.release(spec, row, first["slot_id"])
            self.assertEqual(released["slot_state"], "RESTORED")
            self.assertEqual(released["slot_revision"], first["slot_revision"] + 1)
            self.assertEqual(released["admission_barrier"], "RECOVERY_HOLD")
            self.assertIs(released["control_authorized"], False)
            self.assertEqual(self.store.query(spec.execution_id), row)
            self.assertIsNotNone(self.connection().execute("SELECT 1 FROM reservations WHERE id=?",
                                                          (spec.reservation.id,)).fetchone())

    def test_restore_duplicate_does_not_advance_slot_or_registry(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            released = self.release(spec, row, first["slot_id"])
            before = self.custody()
            duplicate = self.release(spec, row, first["slot_id"])
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(duplicate["slot_revision"], released["slot_revision"])
            self.assertEqual(self.custody(), before)

    def test_restore_remains_recordable_after_start_unknown_mode_off_and_role_change(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.connection().execute("UPDATE adaptive_runtime SET mode='off',admission_barrier='RECOVERY_HOLD'")
            self.connection().execute("""UPDATE managed_executions SET role='protected',priority='P0',
                state='START_UNKNOWN',launch_in_flight=1 WHERE execution_id=?""",
                                      (spec.execution_id,))
            self.connection().execute("""UPDATE reservations SET cpu_units=99,
                writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?""", (spec.reservation.id,))
            self.verifier.overrides = dict(legacy_exclusion=False, active_process_count=None,
                                          process_ids=None, root=None)
            result = self.release(spec, self.store.query(spec.execution_id), first["slot_id"])
            self.assertEqual(result["slot_state"], "RESTORED")
            self.assertEqual(result["admission_barrier"], "RECOVERY_HOLD")
            self.assertEqual(self.connection().execute("SELECT cpu_units FROM reservations WHERE id=?",
                                                      (spec.reservation.id,)).fetchone()[0], 99)

    def test_restore_of_bound_root_needs_no_membership_or_surviving_allocation(self):
        spec, row = self.running()
        with self.policy_scope():
            first = self.begin(spec, row)
            conn = self.connection()
            # Model storage damage in this isolated fixture only; production
            # writer fences must keep refusing ordinary live-allocation deletion.
            conn.execute("DROP TRIGGER adaptive_writer_reservations_delete")
            conn.execute("DELETE FROM reservations WHERE id=?", (spec.reservation.id,))
            self.verifier.overrides = dict(active_process_count=None, process_ids=None,
                                          root=None, legacy_exclusion=False)
            restored = self.release(spec, row, first["slot_id"])
            self.assertEqual(restored["slot_state"], "RESTORED")
            self.assertEqual(restored["admission_barrier"], "RECOVERY_HOLD")
            self.assertEqual(self.store.query(spec.execution_id), row)
            self.assertIsNone(conn.execute("SELECT 1 FROM reservations WHERE id=?",
                                           (spec.reservation.id,)).fetchone())

    def test_restore_requires_current_disabled_and_settled_manifest(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            first = self.begin(spec, row)
            for changes in (dict(current_cpu_disabled=False), dict(recovery_manifest_settled=False)):
                self.verifier.overrides = changes
                with self.subTest(changes=tuple(changes)):
                    self.assert_release_rejected(spec, row, first["slot_id"])

    def test_wrong_slot_cannot_release_the_active_episode(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            self.begin(spec, row)
            self.assert_release_rejected(spec, row, str(uuid4()))

    def test_public_booleans_cannot_replace_control_evidence(self):
        spec, row, _ = self.prepared()
        with self.policy_scope():
            before = self.custody()
            with self.assertRaises(TypeError):
                self.begin(spec, row, current_cpu_disabled=True)
            self.assertEqual(self.custody(), before)

    def archive_blocked(self, kind, *, malformed=False):
        spec, row = self.running(self.spec(kind=kind))
        with self.policy_scope():
            self.begin(spec, row)
            if malformed:
                conn = self.connection()
                conn.execute("PRAGMA ignore_check_constraints=ON")
                conn.execute("UPDATE adaptive_control_slot SET schema_version=99")
                conn.execute("PRAGMA ignore_check_constraints=OFF")
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER,
                                            expected_revision=row["state_revision"], now=NOW + 1)
            self.assertEqual(self.custody(), before)

    def test_direct_archive_refuses_owned_held_slot_without_any_mutation(self):
        self.archive_blocked(AllocationKind.DIRECT)

    def test_routed_archive_refuses_owned_held_slot_without_any_mutation(self):
        self.archive_blocked(AllocationKind.ROUTED)

    def test_direct_archive_refuses_malformed_slot_without_any_mutation(self):
        self.archive_blocked(AllocationKind.DIRECT, malformed=True)

    def test_routed_archive_refuses_malformed_slot_without_any_mutation(self):
        self.archive_blocked(AllocationKind.ROUTED, malformed=True)

    def test_forged_other_execution_id_cannot_hide_slot_from_query_or_archive(self):
        spec, row = self.running()
        with self.policy_scope():
            self.begin(spec, row)
            self.connection().execute("UPDATE adaptive_control_slot SET execution_id=?", (str(uuid4()),))
            before = self.custody()
            with self.assertRaisesRegex(LifecycleError, "control_slot_binding_mismatch"):
                self.store.query_control_slot_locked()
            self.assertEqual(self.custody(), before)
            with self.assertRaisesRegex(LifecycleError, "control_slot_binding_mismatch"):
                self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER,
                                            expected_revision=row["state_revision"], now=NOW + 1)
            self.assertEqual(self.custody(), before)
            self.assertIsNotNone(self.connection().execute("SELECT 1 FROM reservations WHERE id=?",
                                                          (spec.reservation.id,)).fetchone())

    def test_restored_slot_allows_archive_without_clearing_admission_barrier(self):
        spec, row = self.running()
        with self.policy_scope():
            first = self.begin(spec, row)
            self.release(spec, row, first["slot_id"])
            done = self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER,
                                               expected_revision=row["state_revision"], now=NOW + 1)
            self.assertEqual(done["state"], "FINISHED")
            self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
            self.assertEqual(self.slot()["slot_state"], "RESTORED")

    # --- clarification C3: the finished Job's own barrier --------------------

    @contextmanager
    def finished_with_restored_slot(self):
        """One real execution taken to FINISHED, its RESTORED slot still open."""
        spec, row = self.running()
        with self.policy_scope() as guard:
            first = self.begin(spec, row)
            self.release(spec, row, first["slot_id"])
            done = self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER,
                                                expected_revision=row["state_revision"], now=NOW + 1)
            self.assertEqual(done["state"], "FINISHED")
            self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
            yield spec, guard, first["slot_id"]

    def clear_finished(self, spec, guard, slot_id, *, cleared_at=NOW + 2, row=None, runtime=None):
        with self.store._transaction() as conn:
            live = self.store._policy.revalidate(conn, guard)
            values = dict(self.store._get(conn, spec.execution_id)) | (row or {})
            return clear_finished_locked(conn, values, dict(live) | (runtime or {}), guard,
                                         slot_id=slot_id, cleared_at=cleared_at)

    def barrier_clears(self):
        """The lazily created audit rows, or None while the table is absent."""
        conn = self.connection()
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_barrier_clears'").fetchone() is None:
            return None
        return [dict(item) for item in conn.execute("SELECT * FROM adaptive_barrier_clears")]

    def assert_finished_clear_refused(self, spec, guard, slot_id, reason, **changes):
        before = self.custody()
        with self.assertRaises(ControlSlotError) as caught:
            self.clear_finished(spec, guard, slot_id, **changes)
        self.assertEqual(str(caught.exception), reason)
        self.assertEqual(self.custody(), before)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.barrier_clears())

    def test_finished_execution_clears_the_barrier_and_records_one_audit_row(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            slot = self.slot()
            revision = self.runtime()["registry_revision"]
            result = self.clear_finished(spec, guard, slot_id)
            self.assertEqual(result["admission_barrier"], "NONE")
            self.assertEqual(result["registry_revision"], revision + 1)
            self.assertEqual(self.runtime()["admission_barrier"], "NONE")
            # The RESTORED row stays as the durable boundary it always was.
            self.assertEqual(self.slot(), slot)
            self.assertEqual(self.barrier_clears(), [{
                "registry_revision": revision + 1, "execution_id": spec.execution_id,
                "slot_id": slot_id, "slot_revision": slot["slot_revision"],
                "guardian_epoch": EPOCH, "reason": "finished_job",
                "finished_at": NOW + 1, "cleared_at": NOW + 2}])

    def test_a_second_clear_finds_no_held_barrier_and_writes_no_second_row(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.clear_finished(spec, guard, slot_id)
            recorded = self.barrier_clears()
            with self.assertRaises(ControlSlotError) as caught:
                self.clear_finished(spec, guard, slot_id)
            self.assertEqual(str(caught.exception), "control_barrier_not_held")
            self.assertEqual(self.barrier_clears(), recorded)
            self.assertEqual(self.runtime()["admission_barrier"], "NONE")

    def test_a_missing_slot_cannot_clear_a_finished_barrier(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.connection().execute("DELETE FROM adaptive_control_slot")
            self.assert_finished_clear_refused(spec, guard, slot_id, "control_slot_missing")

    def test_another_slot_id_cannot_clear_a_finished_barrier(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.assert_finished_clear_refused(spec, guard, str(uuid4()),
                                               "control_slot_binding_mismatch")

    def test_a_changed_row_binding_cannot_clear_a_finished_barrier(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.assert_finished_clear_refused(spec, guard, slot_id, "control_slot_binding_mismatch",
                                               row={"job_nonce": uuid4().hex})

    def test_a_held_slot_cannot_clear_a_finished_barrier(self):
        spec, row = self.running()
        with self.policy_scope() as guard:
            first = self.begin(spec, row)
            self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
            self.assert_finished_clear_refused(spec, guard, first["slot_id"], "control_slot_unrestored")

    def test_an_unfinished_or_cascaded_row_keeps_the_barrier(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            for row in (dict(state="RUNNING"), dict(launch_sealed=0), dict(launch_in_flight=1),
                        dict(finished_at=None), dict(finished_at=float("nan")),
                        dict(parent_execution_id=str(uuid4())), dict(allocation_kind="parent")):
                with self.subTest(row=tuple(row)):
                    self.assert_finished_clear_refused(spec, guard, slot_id,
                                                       "control_execution_unfinished", row=row)

    def test_an_exhausted_or_changed_registry_revision_keeps_the_barrier(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.assert_finished_clear_refused(spec, guard, slot_id, "control_slot_revision_exhausted",
                                               runtime={"registry_revision": (1 << 63) - 1})
            stale = self.runtime()["registry_revision"] - 1
            self.assert_finished_clear_refused(spec, guard, slot_id, "control_slot_revision_conflict",
                                               runtime={"registry_revision": stale})

    def test_an_invalid_slot_id_or_clear_time_is_never_a_clear(self):
        with self.finished_with_restored_slot() as (spec, guard, slot_id):
            self.assert_finished_clear_refused(spec, guard, "not-a-uuid",
                                               "invalid_control_slot_request")
            for cleared_at in (None, -1.0, float("inf"), "now"):
                with self.subTest(cleared_at=cleared_at):
                    self.assert_finished_clear_refused(spec, guard, slot_id,
                        "invalid_control_slot_request", cleared_at=cleared_at)

    def test_controlling_barrier_blocks_an_already_prepared_launch(self):
        victim, row, _ = self.prepared()
        other, prepared, token = self.prepared()
        with self.policy_scope():
            self.begin(victim, row)
        with self.assertRaises(LifecycleError):
            self.store.claim_launch(other.execution_id, caller=WRAPPER,
                                   expected_revision=prepared["state_revision"], claim_token=token,
                                   spec_hash=other.spec_hash, guardian_epoch=EPOCH)
        self.assertEqual(self.store.query(other.execution_id), prepared)


if __name__ == "__main__":
    unittest.main()
