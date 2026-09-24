"""Real two-ledger admission with explicit portable native/readiness fixtures.

The original daily demand, partition publication, authenticated child protocol,
isolated submission transaction and persistent allocation guards are exercised.
The native backends and readiness scope are synthetic; this is not S2 evidence.
"""
from contextlib import closing, contextmanager
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_partition_admission as partition
from sentinel.adaptive import experiment_host_transport as transport
from sentinel.adaptive import daily_generation
from sentinel.adaptive import operation_waits as waits
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_experiment_host_backing as backing_fixtures
from tests import test_adaptive_experiment_host_transport as transport_fixtures
from tests.test_adaptive_ipc import Clock, wire_frame
from tests.test_adaptive_coordinator import NOW


class ExperimentPartitionAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = backing_fixtures.ExperimentHostBackingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.host = self.fixture.host
        self.context, self.snapshot = self.fixture.snapshot()
        self.operation = self.fixture.operation(snapshot=self.snapshot)
        self.fixture.publish(self.operation)
        self.policy = FixturePolicyProvider(self.snapshot.logon_id)
        self.coordinator = Coordinator(self.host.isolated_ledger.parent,
            db_path=self.host.isolated_ledger, policy_provider=self.policy)
        with closing(sqlite3.connect(self.coordinator.db_path, isolation_level=None)) as conn:
            conn.execute("UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?,"
                "policy_binding_initialized=1 WHERE singleton=1",
                (self.host.spec.isolated_policy_instance_id, self.snapshot.logon_id))
        self.base_store = self.coordinator._managed_lifecycle_store()
        self.daily_policy = self.host.policy
        self.generation = self.host.fixture.generation
        self.daily_transactions = []
        self.readiness_calls = []
        self.deadline = SimpleNamespace(require=lambda: 1000)

        # Only native/source readiness is a fixture. Strict daily backing reads
        # still use real SQL, including the actual allocation and all triggers.
        @contextmanager
        def readiness(paths, *, absent_paths):
            self.assertFalse(self.host.fixture.fixture.policy.active)
            self.assertFalse(self.policy.active)
            self.assertEqual(tuple(paths), (self.host.store.db_path.resolve(), self.coordinator.db_path.resolve()))
            self.assertEqual(tuple(absent_paths), (self.coordinator.db_path.resolve(),))
            # Borrow the real two-ledger lexical group. A no-op here leaves
            # daily POLICY selected while isolated admission enters its store.
            with daily_generation.readiness_scopes(paths, absent_paths=absent_paths):
                yield

        def scoped_readiness(path, *, expected_generation):
            self.assertEqual(expected_generation, self.generation)
            self.assertEqual(path, self.host.store.db_path.resolve())
            self.assertTrue(self.host.fixture.fixture.policy.active)
            self.assertFalse(self.policy.active)
            self.assertFalse(self.daily_transactions)
            self.readiness_calls.append(path)
            return self.deadline

        proof = SimpleNamespace(readiness_scopes=readiness,
            revalidate_transaction=lambda *args, **kwargs: None,
            read_generation=lambda conn: dict(self.generation),
            revalidate_scoped_readiness=scoped_readiness)
        replacement = patch.object(partition, "daily_generation", proof)
        replacement.start()
        self.addCleanup(replacement.stop)
        original_connection = self.host.store._connection

        @contextmanager
        def daily_connection(**kwargs):
            with original_connection(**kwargs) as conn:
                conn.create_function("julianday", 1, lambda value: NOW / 86400 + 2440587.5)
                self.daily_transactions.append(conn)
                try:
                    yield conn
                finally:
                    self.daily_transactions.remove(conn)

        replacement = patch.object(self.host.store, "_connection", daily_connection)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.child_binding = self.bind_child()
        self.adapter = partition.ExperimentPartitionCoordinator(self.coordinator, self.child_binding,
            member_id=self.operation.member_id, reservation_id=self.operation.binding.reservation_id,
            daily_store=self.host.store)
        self.addCleanup(self.remove_synthetic_readiness_owners)

    def remove_synthetic_readiness_owners(self):
        # Fault injection can intentionally quarantine these test-owned scopes.
        # Removing the fixture objects is not a production cleanup receipt.
        paths = {self.host.store.db_path.resolve(), self.coordinator.db_path.resolve()}
        for pool in (daily_generation._READINESS_SCOPES, daily_generation._ABSENCE_SCOPES):
            for key, value in list(pool.items()):
                if value.path in paths:
                    pool.pop(key)

    def bind_child(self):
        parent = self.host.owner._snapshot.wrapper_identity
        child = self.snapshot.wrapper_identity
        endpoint = NativePipeEndpoint(child.logon_id, str(uuid4()), parent)
        with closing(sqlite3.connect(self.host.store.db_path)) as conn:
            daily_policy_id = conn.execute("SELECT policy_instance_id FROM adaptive_runtime").fetchone()[0]
        manifest = transport.ExperimentChildManifest(endpoint, child,
            self.host.spec.scope_id, "a" * 64, "b" * 64,
            self.generation["generation"], self.generation["source_digest"], self.generation["config_digest"],
            str(self.host.store.db_path.resolve()), transport.LedgerFileIdentity.capture(self.host.store.db_path),
            daily_policy_id, str(self.coordinator.db_path.resolve()),
            transport.LedgerFileIdentity.capture(self.coordinator.db_path),
            self.host.spec.isolated_policy_instance_id, self.operation.wrapper_member_id,
            "wrapper", (self.operation.member_id,), str(uuid4()))
        registration = transport.ExperimentChildRegistration(manifest, transport_fixtures.KEY)
        self.child_backend = transport_fixtures.Backend(child)
        self.child_process = VerifiedProcess(self.child_backend, 41, child)
        self.addCleanup(self.child_process.close)
        client = transport.ExperimentChildClient(registration, self.child_process)
        request = transport.BindExperimentChildRequest(manifest)
        challenge = {"version": 1, "kind": "ExperimentChildChallenge", "request_id": manifest.request_id,
            "nonce": transport_fixtures.NONCE, "endpoint_id": endpoint.instance_id,
            "server": parent.to_dict(), "client": child.to_dict()}
        result = {"bound_manifest": manifest.to_dict()}
        response = {"version": 1, "kind": "ExperimentChildResult", "request_id": manifest.request_id,
            "nonce": challenge["nonce"], "result": result,
            "mac": transport_fixtures.wire_mac("result", request.to_dict(), challenge, result)}
        pipe = transport_fixtures.Pipe(parent, wire_frame(challenge) + wire_frame(response))
        with patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()), \
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False), \
                patch.object(transport.NativePipeConnection, "connect", return_value=pipe):
            binding = client.bind()
        self.addCleanup(transport._ORIGINAL_CLIENTS.pop, client._request_key, None)
        self.addCleanup(binding.close)
        return binding

    def rows(self, table):
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM " + table)]

    def assert_empty(self):
        for table in ("queue", "reservations", "managed_executions"):
            self.assertEqual(self.rows(table), [], table)

    def test_actual_partition_uses_original_submission_without_machine_projection_or_daily_release(self):
        before = self.host.fixture.assert_retained(self.host.owner)
        backing_before = self.host.rows(partition.backing.TABLE)
        committed = []
        original_commit = self.coordinator._commit_admission
        def check_fences(conn, transaction):
            self.assertTrue(self.host.fixture.fixture.policy.active)
            self.assertTrue(self.policy.active)
            self.assertFalse(self.daily_transactions)
            self.assertTrue(conn.in_transaction)
            committed.append(transaction)
            original_commit(conn, transaction)
        with patch.object(self.coordinator, "_admit", side_effect=AssertionError("second_budget_forbidden")), \
                patch.object(self.coordinator, "_commit_admission", side_effect=check_fences):
            result = self.adapter.admit_managed(self.context)
        self.assertTrue(result["allowed"])
        self.assertFalse(result["launch_authorized"])
        self.assertEqual(result["state"], "RESERVED")
        self.assertEqual(result["reservation_id"], self.operation.binding.reservation_id)
        allocation, row = self.rows("reservations")[0], self.rows("managed_executions")[0]
        self.assertEqual(row["execution_id"], self.snapshot.execution_id)
        self.assertEqual(row["admission_binding_hash"], self.snapshot.binding_hash)
        self.assertEqual(row["reservation_id"], allocation["id"])
        for key, value in self.snapshot.requested.to_dict().items():
            self.assertEqual(row["floor_" + key], value)
        self.assertEqual(allocation["expires_at"], before[0]["expires_at"])
        self.assertIsNone(allocation["lease_duration_sec"])
        self.assertEqual(allocation["command_text"], "")
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertEqual(self.host.rows(partition.backing.TABLE), backing_before)
        self.assertEqual(len(self.readiness_calls), 1)
        self.assertEqual(len(committed), 1)
        self.assertIsNone(self.adapter._daily_guard)
        self.assertEqual(self.adapter._daily_reads, [])

    def test_exact_original_replay_does_not_renew_or_mint_another_allocation(self):
        original = self.adapter.admit_managed(self.context)
        rows = self.rows("reservations")
        replay = self.adapter.admit_managed(self.context)
        self.assertTrue(replay["reused"])
        self.assertEqual(replay["reservation_id"], original["reservation_id"])
        self.assertEqual(self.rows("reservations"), rows)
        other, _ = self.fixture.snapshot()
        with self.assertRaises(partition.PartitionAdmissionError):
            self.adapter.admit_managed(other)
        self.assertEqual(self.rows("reservations"), rows)

    def test_active_daily_generation_and_isolated_absence_use_actual_group(self):
        row = self.generation
        with closing(sqlite3.connect(self.host.store.db_path)) as conn:
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" + ",".join("?" for _ in row) + ")",
                         tuple(row.values()))
            daily_generation._install_triggers(conn)
            conn.commit()
        with patch.object(daily_generation, "_assert_daily_locations"), \
                patch.object(daily_generation, "verify_import_provenance"), \
                patch.object(daily_generation, "_prove_retained_owner_ready", return_value=None), \
                patch.object(daily_generation, "_revalidate_remote"):
            result = self.adapter.admit_managed(self.context)
        self.assertTrue(result["allowed"])
        self.assertEqual(len(self.rows("reservations")), 1)
        self.assertEqual(self.adapter._daily_reads, [])

    def test_copied_capacity_and_clock_inputs_are_refused_before_submission(self):
        for kwargs in ({"status": {}}, {"config": {}}, {"now": NOW}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(partition.PartitionAdmissionError,
                    "caller_capacity_input_forbidden"):
                self.adapter.admit_managed(self.context, **kwargs)
        self.assert_empty()
        self.assertFalse(self.context._submitted)

    def test_unpublished_exact_reservation_or_changed_file_has_no_capacity(self):
        adapter = partition.ExperimentPartitionCoordinator(self.coordinator, self.child_binding,
            member_id=self.operation.member_id, reservation_id=uuid4().hex, daily_store=self.host.store)
        with self.assertRaisesRegex(partition.backing.BackingError, "binding_missing_or_changed"):
            adapter.admit_managed(self.context)
        self.assertEqual(adapter._daily_reads, [])
        retained = adapter._daily_guard
        self.assertTrue(retained._native_exit_confirmed)
        self.assertTrue(retained._nonce_clear_confirmed)
        with closing(sqlite3.connect(self.host.store.db_path)) as conn:
            self.assertIsNone(conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])
        # A second attempt settles that exact positively released guard, then
        # reaches the original backing rejection instead of a cleanup dead end.
        with self.assertRaisesRegex(partition.backing.BackingError, "binding_missing_or_changed"):
            adapter.admit_managed(self.context)
        self.assertIsNot(adapter._daily_guard, retained)
        with patch.object(partition.LedgerFileIdentity, "capture",
                          return_value=transport.LedgerFileIdentity(1, 1)):
            with self.assertRaisesRegex(partition.PartitionAdmissionError, "ledger_identity_changed"):
                self.adapter.admit_managed(self.context)
        self.assert_empty()

    def test_daily_hold_denies_isolated_insert_and_preserves_original_floor(self):
        before = self.host.fixture.assert_retained(self.host.owner)
        self.host.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaisesRegex(partition.ledger.HostLedgerError, "no_new_work"):
            self.adapter.admit_managed(self.context)
        self.assert_empty()
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)

    def test_real_binding_insert_fault_rolls_back_both_local_rows_and_retains_daily_intent(self):
        before = self.host.fixture.assert_retained(self.host.owner)
        with closing(sqlite3.connect(self.coordinator.db_path, isolation_level=None)) as conn:
            conn.execute("CREATE TRIGGER fail_partition BEFORE INSERT ON managed_executions "
                         "BEGIN SELECT RAISE(ABORT,'partition_insert_fault'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "partition_insert_fault") as raised:
            self.adapter.admit_managed(self.context)
        self.assertIs(raised.exception.experiment_partition_owner, self.adapter)
        self.assert_empty()
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertTrue(self.context._submission_transaction["rolled_back"])
        self.assertTrue(self.context._submission_transaction["connection_closed"])

    def test_real_commit_then_ack_loss_reconciles_same_original_context(self):
        commit = self.coordinator._commit_admission
        def lost_ack(conn, transaction):
            commit(conn, transaction)
            raise OSError("partition_commit_ack_lost")
        with patch.object(self.coordinator, "_commit_admission", side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, "partition_commit_ack_lost"):
                self.adapter.admit_managed(self.context)
        before = self.rows("reservations")
        observed = self.adapter.reconcile_managed(self.context)
        self.assertEqual(observed["state"], "RESERVED")
        replay = self.adapter.admit_managed(self.context)
        self.assertTrue(replay["reused"])
        self.assertEqual(self.rows("reservations"), before)

    def test_cancel_unused_local_claim_keeps_parent_floor_even_after_parent_exits(self):
        before = self.host.fixture.assert_retained(self.host.owner)
        result = self.adapter.admit_managed(self.context)
        self.child_binding._peer._backend.status = IdentityStatus.DEAD
        cancelled = self.adapter.cancel_managed(self.context,
            reservation_id=result["reservation_id"], expected_revision=0, now=NOW + 1)
        self.assertEqual(cancelled["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(self.rows("reservations"), [])
        self.assertEqual(len(self.rows("executions")), 1)
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)

    def test_transaction_commit_is_refused_if_validation_consumes_remaining_budget(self):
        real_commit = partition.commit_managed_admission
        def exceed_after_insert(*args, **kwargs):
            result = real_commit(*args, **kwargs)
            waits._LOCAL.budget.deadline = 0
            return result
        with patch.object(partition, "commit_managed_admission", side_effect=exceed_after_insert):
            with self.assertRaises(waits.OperationWaitExpired):
                self.adapter.admit_managed(self.context)
        self.assert_empty()
        self.assertTrue(self.context._submission_transaction["rolled_back"])

    def test_expensive_readiness_validation_cannot_enter_isolated_submission_after_deadline(self):
        def expensive_deadline_observation():
            waits._LOCAL.budget.deadline = 0
            return 1000
        self.deadline.require = expensive_deadline_observation
        with self.assertRaises(waits.OperationWaitExpired):
            self.adapter.admit_managed(self.context)
        self.assert_empty()
        self.assertFalse(self.context._submitted)
        self.assertTrue(self.adapter._daily_guard._native_exit_confirmed)
        self.assertTrue(self.adapter._daily_guard._nonce_clear_confirmed)

    def test_daily_native_release_uncertainty_retains_guard_and_never_reenters(self):
        before = self.host.fixture.assert_retained(self.host.owner)
        provider = self.host.fixture.fixture.policy
        original = provider.hold
        acquisitions = []
        @contextmanager
        def uncertain_release(binding, *, timeout_ms=250):
            acquisitions.append(binding)
            with original(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise OSError("daily_release_ack_unknown")
        with patch.object(provider, "hold", uncertain_release):
            with self.assertRaisesRegex(OSError, "daily_release_ack_unknown"):
                self.adapter.admit_managed(self.context)
            self.assertIsNotNone(self.adapter._daily_guard)
            self.assertFalse(self.adapter._daily_guard._native_exit_confirmed)
            with self.assertRaisesRegex(partition.PartitionAdmissionError, "daily_native_cleanup_unverified"):
                self.adapter.admit_managed(self.context)
        self.assertEqual(len(acquisitions), 1)
        self.assertEqual(len(self.rows("reservations")), 1)
        # The actual group retains both original scopes when native release is
        # unknown. Read-only reconciliation reports durable state without
        # replacing those owners or granting admission/launch authority.
        pending = tuple(value for pool in (daily_generation._READINESS_SCOPES, daily_generation._ABSENCE_SCOPES)
                        for value in pool.values() if value.path in
                        {self.host.store.db_path.resolve(), self.coordinator.db_path.resolve()})
        self.assertEqual({value.path for value in pending},
                         {self.host.store.db_path.resolve(), self.coordinator.db_path.resolve()})
        self.assertTrue(all(value.error is not None for value in pending))
        observed = self.adapter.reconcile_managed(self.context)
        self.assertEqual(observed["state"], "RESERVED")
        self.assertFalse(observed["allowed"])
        self.assertFalse(observed["launch_authorized"])
        retained = tuple(value for pool in (daily_generation._READINESS_SCOPES, daily_generation._ABSENCE_SCOPES)
                         for value in pool.values() if value.path in
                         {self.host.store.db_path.resolve(), self.coordinator.db_path.resolve()})
        self.assertEqual(retained, pending)
        self.assertFalse(self.adapter._daily_guard._native_exit_confirmed)
        self.assertEqual(self.rows("managed_executions")[0]["state"], "RESERVED")
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertEqual(len(acquisitions), 1)


class OperationWaitTests(unittest.TestCase):
    def test_ordinary_connection_options_and_timeout_are_unchanged(self):
        self.assertEqual(waits.sqlite_options(timeout=10), {"timeout": 10})
        self.assertEqual(waits.remaining_timeout_ms(1000), 1000)

    def test_nested_wait_scope_shares_and_only_shortens_original_deadline(self):
        now = [10.0]
        with patch.object(waits.time, "monotonic", side_effect=lambda: now[0]):
            with waits.bounded_waits() as outer:
                self.assertEqual(outer.deadline, 10.25)
                now[0] = 10.1
                with waits.bounded_waits(milliseconds=50) as inner:
                    self.assertIs(inner, outer)
                    self.assertLessEqual(waits.remaining_timeout_ms(5000), 50)
                self.assertLessEqual(outer.deadline, 10.15)
                now[0] = 10.3
                with self.assertRaises(waits.OperationWaitExpired):
                    outer.require()
                self.assertEqual(waits.remaining_timeout_ms(250), 0)

    def test_actual_sqlite_authorizer_survives_shrinking_timeouts_and_expired_rollback(self):
        now = [10.0]
        observed = []
        with patch.object(waits.time, "monotonic", side_effect=lambda: now[0]), waits.bounded_waits():
            with closing(sqlite3.connect(":memory:", isolation_level=None, **waits.sqlite_options(timeout=10))) as conn:
                conn.execute("CREATE TABLE owned(value)")
                def authorize(action, arg1, arg2, _db, _trigger):
                    if action == sqlite3.SQLITE_PRAGMA:
                        if arg1 != "busy_timeout" or arg2 is None or not 0 <= int(arg2) <= 250:
                            return sqlite3.SQLITE_DENY
                        observed.append(int(arg2))
                    if action == sqlite3.SQLITE_DELETE:
                        return sqlite3.SQLITE_DENY
                    return sqlite3.SQLITE_OK
                conn.set_authorizer(authorize)
                conn.execute("PRAGMA busy_timeout=10000")
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("INSERT INTO owned VALUES(1)")
                now[0] = 10.2
                with self.assertRaises(sqlite3.DatabaseError):
                    conn.execute("DELETE FROM owned")
                now[0] = 10.3
                conn.rollback()
                self.assertEqual(conn.execute("SELECT count(*) FROM owned").fetchone()[0], 0)
                self.assertEqual(observed[-1], 0)
                self.assertLessEqual(max(observed), 250)
                self.assertFalse(conn.in_transaction)
