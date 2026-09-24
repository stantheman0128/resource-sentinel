"""Actual daily SQLite intents, with explicit synthetic wrapper observations.

These tests do not perform isolated admission or mint child-local authority.
ManagedAdmission builds its real immutable snapshot with a synthetic retained
current-process provider before SQL. Only the original parent may publish it.
"""
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_host_backing as backing
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand, Role
from tests import test_adaptive_admission_context as admission_fixtures
from tests import test_adaptive_experiment_host_ledger as host_fixtures
from tests import test_adaptive_experiment_host_scope as scope_fixtures


MIB = 1 << 20


class ExperimentHostBackingTests(unittest.TestCase):
    def setUp(self):
        self.host = host_fixtures.ExperimentHostLedgerTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.host.declare()
        self.sequence = 0

    def snapshot(self, requested=None):
        self.sequence += 1
        original = self.host.owner._snapshot.wrapper_identity
        identity = ProcessIdentity(original.pid, original.created_filetime_100ns + 10000 + self.sequence, original.logon_id)
        process = admission_fixtures.FakeCurrentProcess(identity)
        with patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=process):
            context = self.host.fixture.fixture.context(requested=requested or ResourceDemand(.1, 64*MIB, 64*MIB, 0))
            observed = context.snapshot()
        return context, observed

    def operation(self, *, member=None, wrapper=None, snapshot=None, reservation_id=None):
        if snapshot is None:
            _, snapshot = self.snapshot()
        wrapper = wrapper or self.host.actor(role="wrapper", identity=snapshot.wrapper_identity)[0]
        member = member or self.host.reserve(kind="workload", role="workload", requested=snapshot.requested)
        operation = backing.ParentAdmissionBacking.prepare(scope=self.host.scope_owner,
            member_id=member.member_id, wrapper_member_id=wrapper.member_id,
            snapshot=snapshot, reservation_id=reservation_id or uuid4().hex)
        return operation

    def publish(self, operation):
        with self.host.locked() as (conn, guard):
            value = backing.publish_locked(conn, operation=operation, policy=self.host.policy, guard=guard)
            conn.commit()
            return value

    def validate(self, operation, **overrides):
        with self.host.locked() as (conn, guard):
            return backing.validate_backing_locked(conn, **(dict(scope_id=self.host.spec.scope_id,
                member_id=operation.member_id, wrapper_member_id=operation.wrapper_member_id,
                binding=operation.binding, policy=self.host.policy, guard=guard) | overrides))

    def job(self, operation, *, kind="managed", reservation_id=None):
        guardian = self.host.actor(role="guardian" if kind == "managed" else "query_owner")[0]
        nonce = uuid4().hex
        execution = operation.binding.execution_id
        value = ledger.JobBinding(operation.member_id, kind,
            "Local\\ResourceSentinel.Job." + execution + "." + nonce if kind == "managed" else
            "Local\\ResourceSentinel.Test.Job." + nonce, nonce, guardian.member_id,
            operation.wrapper_member_id if kind == "managed" else None,
            execution if kind == "managed" else None,
            (reservation_id or operation.binding.reservation_id) if kind == "managed" else None)
        with self.host.locked() as (conn, guard):
            ledger.publish_job_locked(conn, scope=self.host.scope_owner, binding=value,
                                      policy=self.host.policy, guard=guard)
            conn.commit()
        return value

    def test_parent_intent_binds_actual_snapshot_without_second_capacity_or_child_authority(self):
        operation = self.operation()
        isolated_before = self.host.isolated_ledger.read_bytes()
        floor = self.host.fixture.assert_retained(self.host.owner)
        result = self.publish(operation)
        self.assertEqual(result, self.validate(operation))
        self.assertEqual(result.binding, operation.binding)
        row = self.host.rows(backing.TABLE)[0]
        self.assertEqual(row["spec_hash"], operation._snapshot.spec_hash)
        self.assertEqual(row["request_spec_hash"], operation._snapshot.request.spec_hash)
        self.assertNotEqual(row["request_spec_hash"], row["spec_hash"])
        self.assertEqual(row["admission_binding_hash"], operation._snapshot.binding_hash)
        self.assertEqual(json.loads(row["requested_json"]), operation._snapshot.requested.to_dict())
        self.assertEqual(row["isolated_reservation_id"], operation.binding.reservation_id)
        self.assertNotIn("ipc_auth_key", row)
        self.assertNotIn(operation._snapshot.ipc_auth_key.hex(), json.dumps(row))
        self.assertNotIn(operation._snapshot.claim_token_hash, json.dumps(row))
        self.assertEqual(self.host.isolated_ledger.read_bytes(), isolated_before)
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), floor)
        # A backed but unlaunched creation obligation still blocks legacy writes.
        with self.assertRaisesRegex(ledger.HostLedgerError, "member_publication_pending"):
            self.host.inventory()

    def test_exact_original_replay_keeps_same_row_revision_and_reservation_after_commit_ack_loss(self):
        operation = self.operation()
        with self.assertRaisesRegex(RuntimeError, "synthetic_ack_loss"):
            with self.host.locked() as (conn, guard):
                backing.publish_locked(conn, operation=operation, policy=self.host.policy, guard=guard)
                conn.commit()
                raise RuntimeError("synthetic_ack_loss")
        before, revision = self.host.rows(backing.TABLE), self.host.revision()
        self.assertIs(backing.ParentAdmissionBacking.prepare(scope=self.host.scope_owner,
            member_id=operation.member_id, wrapper_member_id=operation.wrapper_member_id,
            snapshot=operation._snapshot, reservation_id=operation.binding.reservation_id), operation)
        self.assertEqual(self.publish(operation), self.validate(operation))
        self.assertEqual(self.host.rows(backing.TABLE), before)
        self.assertEqual(self.host.revision(), revision)

    def test_copy_or_different_payload_cannot_reuse_original_member_operation(self):
        operation = self.operation()
        self.publish(operation)
        for snapshot, reservation in ((replace(operation._snapshot), operation.binding.reservation_id),
                (operation._snapshot, uuid4().hex)):
            with self.subTest(reservation=reservation), self.assertRaisesRegex(backing.BackingError, "original_operation_changed"):
                backing.ParentAdmissionBacking.prepare(scope=self.host.scope_owner, member_id=operation.member_id,
                    wrapper_member_id=operation.wrapper_member_id, snapshot=snapshot, reservation_id=reservation)
        with self.assertRaisesRegex(backing.BackingError, "original_operation_required"):
            backing.ParentAdmissionBacking(operation.scope, operation.member_id, operation.wrapper_member_id,
                operation._snapshot, operation.binding)

    def test_one_wrapper_execution_and_reservation_cannot_back_a_second_member(self):
        operation = self.operation()
        self.publish(operation)
        second = self.host.reserve(kind="workload", role="workload", requested=operation.binding.requested)
        other = backing.ParentAdmissionBacking.prepare(scope=self.host.scope_owner, member_id=second.member_id,
            wrapper_member_id=operation.wrapper_member_id, snapshot=operation._snapshot,
            reservation_id=operation.binding.reservation_id)
        before = self.host.rows(backing.TABLE)
        with self.assertRaises(sqlite3.DatabaseError):
            self.publish(other)
        self.assertEqual(self.host.rows(backing.TABLE), before)
        self.host.fixture.assert_retained(self.host.owner)

    def test_exact_member_envelope_and_already_published_wrapper_are_required(self):
        _, snapshot = self.snapshot()
        member = self.host.reserve(kind="workload", role="workload", requested=ResourceDemand(.2, 64*MIB, 64*MIB, 0))
        wrapper = self.host.actor(role="wrapper", identity=snapshot.wrapper_identity)[0]
        operation = self.operation(member=member, wrapper=wrapper, snapshot=snapshot)
        with self.assertRaisesRegex(backing.BackingError, "partition_binding_changed"):
            self.publish(operation)
        self.assertIsNone(self.host.connection().execute("SELECT 1 FROM sqlite_master WHERE name=?", (backing.TABLE,)).fetchone())
        with self.assertRaisesRegex(backing.BackingError, "snapshot_scope_invalid"):
            backing.ParentAdmissionBacking.prepare(scope=self.host.scope_owner, member_id=str(uuid4()),
                wrapper_member_id=wrapper.member_id, snapshot=replace(snapshot, role="background"), reservation_id=uuid4().hex)

    def test_valid_digest_raw_insert_and_replace_have_no_original_write_authority(self):
        operation = self.operation()
        self.publish(operation)
        before = self.host.rows(backing.TABLE)
        row = dict(before[0], member_id=str(uuid4()), isolated_execution_id=str(uuid4()),
                   isolated_reservation_id=uuid4().hex, request_key="e" * 64, wrapper_member_id=str(uuid4()))
        row["binding_sha256"] = ledger._digest({key: value for key, value in row.items() if key != "binding_sha256"})
        with self.host.locked() as (conn, guard):
            for action in ("INSERT", "INSERT OR REPLACE"):
                with self.subTest(action=action), self.assertRaises(sqlite3.DatabaseError):
                    conn.execute(action + " INTO " + backing.TABLE + " VALUES(" +
                        ",".join("?" for _ in backing.FIELDS) + ")", tuple(row[key] for key in backing.FIELDS))
            conn.commit()
        self.assertEqual(self.host.rows(backing.TABLE), before)

    def test_failed_postcheck_rolls_back_schema_row_and_revision_but_keeps_original_attempt(self):
        operation = self.operation()
        revision = self.host.revision()
        with self.host.locked() as (conn, guard):
            with patch.object(backing, "validate_backing_locked", side_effect=backing.BackingError("injected_postcheck")):
                with self.assertRaisesRegex(backing.BackingError, "injected_postcheck"):
                    backing.publish_locked(conn, operation=operation, policy=self.host.policy, guard=guard)
            conn.commit()
        self.assertEqual(self.host.revision(), revision)
        self.assertIsNone(self.host.connection().execute("SELECT 1 FROM sqlite_master WHERE name=?", (backing.TABLE,)).fetchone())
        self.assertIs(self.host.scope_owner._backings[operation.member_id], operation)
        self.publish(operation)

    def test_hold_keeps_original_intent_and_readonly_replay_but_forbids_new_binding(self):
        operation = self.operation()
        self.publish(operation)
        pending = self.operation()
        before = self.host.rows(backing.TABLE)
        conn = self.host.connection()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',hold_reason='reservation_expired',"
            "state_revision=state_revision+1 WHERE execution_id=?", (self.host.owner._snapshot.execution_id,))
        revision = self.host.revision()
        self.assertEqual(self.publish(operation), self.validate(operation))
        with self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
            self.publish(pending)
        self.assertEqual(self.host.rows(backing.TABLE), before)
        self.assertEqual(self.host.revision(), revision)
        self.host.fixture.assert_retained(self.host.owner)

    def test_reserved_expiry_allows_readonly_replay_but_refuses_new_admission_or_intent(self):
        operation = self.operation()
        self.publish(operation)
        pending = self.operation()
        before, revision = self.host.rows(backing.TABLE), self.host.revision()
        expiration = self.host.rows("reservations")[0]["expires_at"]
        with self.host.locked() as (conn, guard):
            arguments = dict(scope_id=self.host.spec.scope_id, member_id=operation.member_id,
                wrapper_member_id=operation.wrapper_member_id, binding=operation.binding, policy=self.host.policy, guard=guard)
            observation = backing.validate_admission_locked(conn, **arguments)
            self.assertEqual(observation.daily_expires_at, expiration)
            conn.create_function("julianday", 1, lambda value: (expiration + 1) / 86400 + 2440587.5)
            self.assertEqual(backing.validate_backing_locked(conn, **arguments), observation)
            self.assertEqual(backing.publish_locked(conn, operation=operation, policy=self.host.policy, guard=guard), observation)
            with self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
                backing.validate_admission_locked(conn, **arguments)
            with self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
                backing.publish_locked(conn, operation=pending, policy=self.host.policy, guard=guard)
        self.assertEqual(self.host.rows(backing.TABLE), before)
        self.assertEqual(self.host.revision(), revision)
        self.assertEqual(self.host.rows("managed_executions")[0]["state"], "RESERVED")
        self.host.fixture.assert_retained(self.host.owner)

    def test_exact_child_read_rejects_changed_request_spec_and_peer(self):
        operation = self.operation()
        self.publish(operation)
        identity = operation.binding.wrapper_identity
        for changed in (replace(operation.binding, request_spec_hash="e" * 64),
                replace(operation.binding, spec_hash="d" * 64),
                replace(operation.binding, wrapper_identity=ProcessIdentity(identity.pid,
                    identity.created_filetime_100ns + 1, identity.logon_id))):
            with self.subTest(binding=changed), self.assertRaisesRegex(backing.BackingError, "binding_missing_or_changed"):
                self.validate(operation, binding=changed)

    def test_exact_production_preparation_rejects_undeclared_member_and_missing_managed_backing(self):
        fixture = scope_fixtures.ProductionExperimentScopeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        owner = fixture.prepare()
        registered = owner.registered_scope
        claim = ledger.MemberClaim(str(uuid4()), "workload", "workload", ResourceDemand(.1, 64*MIB, 64*MIB, 0))
        execution, nonce = str(uuid4()), uuid4().hex
        job = ledger.JobBinding(claim.member_id, "managed",
            "Local\\ResourceSentinel.Job." + execution + "." + nonce, nonce,
            str(uuid4()), str(uuid4()), execution, uuid4().hex)
        with owner._operation() as guard:
            with owner._sql(owner.demand.ledger_path, write=True) as conn:
                with self.assertRaisesRegex(ledger.HostLedgerError, "declared_original_member_required"):
                    ledger.reserve_member_locked(conn, scope=registered, claim=claim, policy=owner._daily_policy, guard=guard)
                with self.assertRaisesRegex(ledger.HostLedgerError, "admission_backing_required"):
                    ledger.publish_job_locked(conn, scope=registered, binding=job, policy=owner._daily_policy, guard=guard)
        self.assertEqual(fixture.fixture.rows(ledger.MEMBERS_TABLE), [])
        self.assertEqual(fixture.fixture.rows(ledger.JOBS_TABLE), [])

    def test_original_production_scope_publishes_exact_backing_and_matching_job_without_second_capacity(self):
        fixture = scope_fixtures.ProductionExperimentScopeTests()
        fixture.MEMBER_ROLES = ("wrapper", "guardian", "workload")
        fixture.MEMBER_DEMAND = ResourceDemand(.1, 64*MIB, 64*MIB, 0)
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        floor = fixture.fixture.assert_retained(fixture.demand)
        owner = fixture.prepare()
        wrapper, guardian, member = fixture.members
        for claim in fixture.members:
            owner.reserve_member(claim)
        # A real ManagedAdmission snapshot is captured before SQL. The retained
        # process provider is explicitly synthetic; no native creation is claimed.
        context = fixture.fixture.fixture.context(requested=member.requested)
        snapshot = context.snapshot()
        identity = snapshot.wrapper_identity
        guardian_identity = ProcessIdentity(identity.pid + 1, identity.created_filetime_100ns + 1, identity.logon_id)
        with owner._operation() as guard:
            with owner._sql(owner.demand.ledger_path, write=True) as conn:
                for claim, actor in ((wrapper, identity), (guardian, guardian_identity)):
                    ledger.publish_actor_locked(conn, scope=owner.registered_scope, member_id=claim.member_id,
                        actor=actor, policy=owner._daily_policy, guard=guard)
        operation = backing.ParentAdmissionBacking.prepare(scope=owner.registered_scope,
            member_id=member.member_id, wrapper_member_id=wrapper.member_id,
            snapshot=snapshot, reservation_id=uuid4().hex)
        nonce = uuid4().hex
        job = ledger.JobBinding(member.member_id, "managed",
            "Local\\ResourceSentinel.Job." + snapshot.execution_id + "." + nonce, nonce,
            guardian.member_id, wrapper.member_id, snapshot.execution_id, operation.binding.reservation_id)
        with owner._operation() as guard:
            with owner._sql(owner.demand.ledger_path, write=True) as conn:
                observation = backing.publish_locked(conn, operation=operation, policy=owner._daily_policy, guard=guard)
                ledger.publish_job_locked(conn, scope=owner.registered_scope, binding=job,
                    policy=owner._daily_policy, guard=guard)
                inventory = ledger.read_locked(conn, policy=owner._daily_policy, guard=guard)
        self.assertIs(owner.registered_scope.preparation, owner)
        self.assertIs(owner.registered_scope._backings[member.member_id], operation)
        self.assertEqual(inventory.admission_backings, (observation,))
        self.assertEqual(inventory.managed_job_names, (job.job_name,))
        self.assertEqual(inventory.identities, frozenset((identity, guardian_identity)))
        self.assertEqual(fixture.fixture.assert_retained(fixture.demand), floor)
        self.assertEqual(len(fixture.fixture.rows(backing.TABLE)), 1)

    def test_job_must_match_same_backing(self):
        operation = self.operation()
        self.publish(operation)
        with self.assertRaisesRegex(backing.BackingError, "job_binding_changed"):
            self.job(operation, reservation_id=uuid4().hex)
        self.assertEqual(self.host.rows(ledger.JOBS_TABLE), [])
        self.host.fixture.assert_retained(self.host.owner)

    def test_query_fixture_cannot_consume_managed_backing(self):
        operation = self.operation()
        self.publish(operation)
        with self.assertRaisesRegex(backing.BackingError, "job_binding_changed"):
            self.job(operation, kind="query_only")
        self.assertEqual(self.host.rows(ledger.JOBS_TABLE), [])

    def test_another_member_cannot_alias_a_pending_execution_and_hide_its_managed_slot(self):
        operation = self.operation()
        self.publish(operation)
        member = self.host.reserve(kind="workload", role="workload", requested=operation.binding.requested)
        guardian = self.host.actor(role="guardian")[0]
        wrapper = self.host.actor(role="wrapper")[0]
        nonce = uuid4().hex
        job = ledger.JobBinding(member.member_id, "managed",
            "Local\\ResourceSentinel.Job." + operation.binding.execution_id + "." + nonce, nonce,
            guardian.member_id, wrapper.member_id, operation.binding.execution_id, operation.binding.reservation_id)
        with self.host.locked() as (conn, guard):
            with self.assertRaisesRegex(backing.BackingError, "job_binding_changed"):
                ledger.publish_job_locked(conn, scope=self.host.scope_owner, binding=job,
                    policy=self.host.policy, guard=guard)
            conn.commit()
        self.assertEqual(self.host.rows(ledger.JOBS_TABLE), [])
        self.assertEqual(self.validate(operation).binding, operation.binding)

    def test_matching_job_consumes_its_existing_managed_slot_once(self):
        operation = self.operation()
        self.publish(operation)
        actual = self.job(operation)
        inventory = self.host.inventory()
        self.assertEqual(inventory.managed_job_names, (actual.job_name,))
        self.assertEqual(inventory.admission_backings, (self.validate(operation),))

    def test_pending_backing_and_ordinary_jobs_share_ten_managed_slots(self):
        for _ in range(9):
            self.host.production_job()
        first = self.operation()
        self.publish(first)
        second = self.operation()
        before = self.host.rows(backing.TABLE)
        with self.assertRaisesRegex(RuntimeError, "job_limit"):
            self.publish(second)
        self.assertEqual(self.host.rows(backing.TABLE), before)
        self.assertEqual(len(self.host.rows("reservations")), 10)

    def test_inventory_charges_backing_to_same_row_budget_and_refuses_partial_schema(self):
        operation = self.operation()
        with self.host.locked() as (conn, guard):
            old = ledger._inventory(conn, self.host.policy, guard)[0]
        self.publish(operation)
        with self.host.locked() as (conn, guard):
            current, _, tables = ledger._inventory(conn, self.host.policy, guard)
            self.assertEqual(current.rows, old.rows + 1)
            self.assertEqual(current.host_rows, old.host_rows + 1)
            budget = ledger._Budget()
            budget.charge(ledger.MAX_ROWS, 0)
            marker = operation.member_id.encode()
            def no_payload(value):
                if value == marker:
                    raise AssertionError("backing exceeded remaining shared row budget")
                return value.decode("utf-8")
            conn.text_factory = no_payload
            revision = conn.execute("SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0]
            with self.assertRaisesRegex(backing.BackingError, "history_or_partition_limit"):
                backing.read_for_inventory_locked(conn, tables=tables, revision=revision, budget=budget)
        conn = self.host.connection()
        conn.execute("DROP TRIGGER " + next(iter(backing.GUARDS)))
        with self.assertRaises(ledger.HostLedgerError):
            self.host.inventory()

    def test_locked_publication_does_not_call_native_getters_or_filesystem(self):
        context, snapshot = self.snapshot()
        operation = self.operation(snapshot=snapshot)
        with self.host.locked() as (conn, guard):
            with patch.object(context, "snapshot", side_effect=AssertionError("native getter in SQL")), \
                    patch.object(Path, "stat", side_effect=AssertionError("filesystem in SQL")), \
                    patch.object(Path, "resolve", side_effect=AssertionError("filesystem in SQL")):
                backing.publish_locked(conn, operation=operation, policy=self.host.policy, guard=guard)
            conn.commit()


if __name__ == "__main__":
    unittest.main()
