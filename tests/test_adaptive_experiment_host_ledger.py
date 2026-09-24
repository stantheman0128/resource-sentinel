"""Isolated SQLite host partitions; synthetic identity/readiness, no native work.

Reusable ExperimentHostLedgerTests fixture supports actual consumer tests. The
real admission, immutable demand rows, POLICY transactions and SQL guards run;
only the existing portable native/readiness collaborators are synthetic.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import hashlib
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import experiment_demand as demand
from sentinel.adaptive import experiment_host_ledger as host
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand
from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleStore
from tests.test_adaptive_coordinator import NOW
from tests import test_adaptive_experiment_demand as demand_fixtures
from tests import test_adaptive_experiment_exclusion as exclusion_fixtures
from tests import test_adaptive_daily_successor_history as succession_fixtures
from tests import test_adaptive_daily_successor_epoch as epoch_fixtures


MIB = 1 << 20


class ExperimentHostLedgerTests(unittest.TestCase):
    SUITE = "P4"

    def setUp(self):
        self.fixture = demand_fixtures.ExperimentDemandTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        declaration = demand.ExperimentDeclaration(str(uuid4()), self.SUITE, "c" * 64,
            ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        self.owner = demand.DailyExperimentDemand.capture(declaration, self.fixture.scope)
        self.fixture.owners.append(self.owner)
        self.admitted = self.fixture.coordinator.admit_experiment(self.owner)
        self.assertTrue(self.admitted["allowed"])
        override = patch.object(host, "daily_generation", self.fixture.proof)
        override.start()
        self.addCleanup(override.stop)
        self.store = LifecycleStore(self.fixture.coordinator.db_path,
                                   policy_provider=self.fixture.fixture.policy)
        self.policy = self.store._policy
        self.logon = self.owner._snapshot.logon_id
        self.isolated_ledger = self.fixture.scope / "isolated.db"
        self.isolated_ledger.touch()
        info = self.isolated_ledger.stat()
        self.spec = host.HostScopeSpec(str(uuid4()), self.SUITE, str(self.isolated_ledger),
                                     (info.st_dev, info.st_ino), str(uuid4()))
        self.scope_owner = None
        self.counter = 1000
        self.addCleanup(self.remove_original_scope)

    def remove_original_scope(self):
        key = self.owner.declaration.experiment_id
        original = host._ORIGINALS.get(key)
        if original is not None and original.demand is self.owner:
            del host._ORIGINALS[key]

    def connection(self):
        conn = self.fixture.fixture.conn()
        # Match the actual portable admission fixture's clock on every SQL
        # connection. Only explicit expiry cases override this test-only clock.
        conn.create_function("julianday", 1, lambda value: NOW / 86400 + 2440587.5)
        return conn

    @contextmanager
    def locked(self):
        guard = self.policy.prepare(self.logon)
        primary = None
        with self.policy.hold(guard):
            conn = self.connection()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn, guard
            except BaseException as error:
                primary = error
            finally:
                if conn.in_transaction:
                    conn.rollback()
        if primary is not None:
            raise primary

    def declare(self):
        with self.locked() as (conn, guard):
            self.scope_owner = host.declare_scope_locked(conn, demand=self.owner, spec=self.spec,
                                                        policy=self.policy, guard=guard)
            conn.commit()
        return self.scope_owner

    def reserve(self, *, kind="infrastructure", role="observer", requested=None, claim=None):
        if self.scope_owner is None:
            self.declare()
        claim = claim or host.MemberClaim(str(uuid4()), kind, role,
                                         requested or ResourceDemand(.001, MIB, MIB, 0))
        with self.locked() as (conn, guard):
            host.reserve_member_locked(conn, scope=self.scope_owner, claim=claim,
                                       policy=self.policy, guard=guard)
            conn.commit()
        return claim

    def actor(self, claim=None, *, role="observer", identity=None):
        claim = claim or self.reserve(role=role)
        self.counter += 1
        identity = identity or ProcessIdentity(self.counter,
            self.owner._snapshot.wrapper_identity.created_filetime_100ns + self.counter, self.logon)
        with self.locked() as (conn, guard):
            host.publish_actor_locked(conn, scope=self.scope_owner, member_id=claim.member_id,
                                      actor=identity, policy=self.policy, guard=guard)
            conn.commit()
        return claim, identity

    def job(self, *, kind="managed", guardian=None, wrapper=None):
        guardian = guardian or self.actor(role="guardian" if kind == "managed" else "query_owner")[0]
        if kind == "managed":
            wrapper = wrapper or self.actor(role="wrapper")[0]
        member = self.reserve(kind="workload", role="workload")
        execution, nonce = str(uuid4()), uuid4().hex
        binding = host.JobBinding(member.member_id, kind,
            ("Local\\ResourceSentinel.Job." + execution + "." + nonce if kind == "managed" else
             "Local\\ResourceSentinel.Test.Job." + nonce), nonce, guardian.member_id,
            wrapper.member_id if wrapper else None,
            execution if kind == "managed" else None, uuid4().hex if kind == "managed" else None)
        with self.locked() as (conn, guard):
            host.publish_job_locked(conn, scope=self.scope_owner, binding=binding,
                                    policy=self.policy, guard=guard)
            conn.commit()
        return binding

    def inventory(self):
        with self.locked() as (conn, guard):
            return host.read_locked(conn, policy=self.policy, guard=guard)

    def rows(self, table):
        return [dict(row) for row in self.connection().execute("SELECT * FROM " + table)]

    def revision(self):
        return self.connection().execute("SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0]

    def production_job(self):
        """Actual admission, synthetic ordinary Job metadata; never native."""
        fixture = self.fixture.fixture
        admitted = fixture.admit(fixture.context(requested=ResourceDemand(.1, 128*MIB, 128*MIB, 0)))
        self.assertTrue(admitted["allowed"])
        nonce = uuid4().hex
        name = "Local\\ResourceSentinel.Job." + admitted["execution_id"] + "." + nonce
        conn = self.connection()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        conn.execute("UPDATE managed_executions SET state='RUNNING',job_name=?,job_nonce=? WHERE execution_id=?",
                     (name, nonce, admitted["execution_id"]))
        return name

    def test_absence_is_readonly_but_partial_registry_never_means_empty(self):
        before = self.revision()
        self.assertEqual(self.inventory().scope_count, 0)
        self.assertIsNone(self.inventory().prior_exclusion)
        self.assertEqual(self.revision(), before)
        self.assertIsNone(self.connection().execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                                   (host.SCOPES_TABLE,)).fetchone())
        self.connection().execute(host.SCHEMA[host.MEMBERS_TABLE])
        with self.assertRaisesRegex(host.HostLedgerError, "schema_invalid"):
            self.inventory()

    def test_one_original_aggregate_is_sole_capacity_and_replay_is_original_only(self):
        before = self.fixture.assert_retained(self.owner)
        original = self.declare()
        revision = self.revision()
        self.assertIs(self.declare(), original)
        self.assertEqual(self.revision(), revision)
        with self.locked() as (conn, guard):
            with self.assertRaisesRegex(host.HostLedgerError, "original_scope_changed"):
                host.declare_scope_locked(conn, demand=self.owner, spec=replace(self.spec),
                                          policy=self.policy, guard=guard)
        self.assertEqual(self.fixture.assert_retained(self.owner), before)
        self.assertEqual(self.inventory().scope_count, 1)
        self.assertEqual(self.rows("worker_reservations"), [])
        self.assertEqual(len(self.rows("reservations")), 1)

    def test_experiment_succession_epoch_and_host_consume_one_remaining_row_budget(self):
        self.actor()
        archive = succession_fixtures.SuccessorHistoryReaderTests()
        archive.setUp()
        self.addCleanup(archive.doCleanups)
        epoch_fixture = epoch_fixtures.SuccessorEpochReaderTests()
        epoch_fixture.setUp()
        self.addCleanup(epoch_fixture.doCleanups)
        record = archive.record()
        raw = succession_fixtures.canonical(record)
        digest = hashlib.sha256(host.daily_successor_history._DOMAIN + raw.encode()).hexdigest()
        policy_binding = epoch_fixtures.PolicyBinding(record["policy"]["instance_id"], record["policy"]["logon_id"])
        audit = dict(epoch_fixture.row, transition_id=record["transition_id"], succession_sha256=digest,
            successor_generation=record["successor"]["generation"],
            policy_instance_id=policy_binding.instance_id, policy_logon_id=policy_binding.logon_id,
            supervisor_instance_id=epoch_fixtures.supervisor_instance_binding(policy_binding).instance_id)
        with self.locked() as (conn, guard):
            for statement in (host.daily_successor_history._SCHEMA,
                    *host.daily_successor_history._TRIGGERS.values(), host.daily_successor_epoch._SCHEMA,
                    *host.daily_successor_epoch._TRIGGERS.values()):
                conn.execute(statement)
            conn.execute("INSERT INTO " + host.daily_successor_history.TABLE + " VALUES(?,?,?,?,?,?)",
                (1, record["transition_id"], record["predecessor"]["generation"],
                 record["successor"]["generation"], raw, digest))
            conn.execute("INSERT INTO " + host.daily_successor_epoch.TABLE + " VALUES(" +
                ",".join("?" for _ in host.daily_successor_epoch._FIELDS) + ")",
                tuple(audit[name] for name in host.daily_successor_epoch._FIELDS))
            old = host.experiment_history.verify_experiment_history_locked(conn)
            inventory = host.read_locked(conn, policy=self.policy, guard=guard)
            self.assertEqual(inventory.rows, old.rows_used + 2 + inventory.host_rows)
            self.assertIsNotNone(inventory.prior_exclusion)
            # Model rows already spent by the enclosing inventory. The real
            # readers below must consume exactly the remainder, once each.
            budget = host._Budget()
            budget.charge(host.MAX_ROWS - old.rows_used - 2, 0)
            host._history_locked(conn, budget)
            self.assertEqual(budget.rows, host.MAX_ROWS)
            forbidden = {self.spec.scope_id.encode(), audit["attempt_id"].encode()}
            def reject_overflow(value):
                if value in forbidden:
                    raise AssertionError("exhausted aggregate budget materialized payload")
                return value.decode("utf-8")
            conn.text_factory = reject_overflow
            with self.assertRaisesRegex(host.HostLedgerError, "history_exhausted"):
                host._rows(conn, host.SCOPES_TABLE, budget)
            budget = host._Budget()
            budget.charge(host.MAX_ROWS - old.rows_used - 1, 0)
            with self.assertRaisesRegex(RuntimeError, "rows_exceeded"):
                host._history_locked(conn, budget)

    def test_failed_declaration_postcheck_rolls_back_ddl_scope_and_revision_even_if_caller_commits(self):
        before = self.revision()
        with self.locked() as (conn, guard):
            with patch.object(host, "read_locked", side_effect=host.HostLedgerError("history_exhausted")):
                with self.assertRaisesRegex(host.HostLedgerError, "history_exhausted"):
                    host.declare_scope_locked(conn, demand=self.owner, spec=self.spec,
                                              policy=self.policy, guard=guard)
            conn.commit()
        self.assertEqual(self.revision(), before)
        self.assertIsNone(self.connection().execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                                   (host.SCOPES_TABLE,)).fetchone())
        # The same retained original publication can settle, without a new ID.
        original = host._ORIGINALS[self.owner.declaration.experiment_id]
        self.assertIs(self.declare(), original)

    def test_unrecognized_unique_index_is_not_a_supported_schema(self):
        self.actor()
        self.connection().execute("CREATE UNIQUE INDEX unexpected_host_role ON " + host.MEMBERS_TABLE + "(role)")
        with self.assertRaisesRegex(host.HostLedgerError, "schema_invalid"):
            self.inventory()

    def test_registered_scope_and_mutations_require_real_held_daily_policy(self):
        self.declare()
        claim = host.MemberClaim(str(uuid4()), "infrastructure", "helper", ResourceDemand(.001, MIB, MIB, 0))
        with self.locked() as (conn, guard):
            for policy, candidate in ((Mock(), guard), (self.policy, replace(guard, nonce=str(uuid4())))):
                with self.subTest(policy=type(policy)), self.assertRaises((host.HostLedgerError, PolicyError)):
                    host.reserve_member_locked(conn, scope=self.scope_owner, claim=claim, policy=policy, guard=candidate)
        conn = self.connection()
        conn.execute("BEGIN")
        try:
            with self.assertRaises((host.HostLedgerError, PolicyError)):
                host.read_locked(conn, policy=self.policy, guard=guard)
        finally:
            conn.rollback()

    def test_infrastructure_and_workload_claims_spend_same_immutable_aggregate(self):
        self.actor(self.reserve(requested=ResourceDemand(.3, 512*MIB, 768*MIB, 0)))
        before = self.rows(host.MEMBERS_TABLE)
        with self.assertRaisesRegex(host.HostLedgerError, "aggregate_demand_exceeded"):
            self.reserve(kind="workload", role="workload", requested=ResourceDemand(.21, MIB, MIB, 0))
        self.assertEqual(self.rows(host.MEMBERS_TABLE), before)
        self.fixture.assert_retained(self.owner)

    def test_pending_actor_and_unmanaged_workload_block_legacy_read_until_publication(self):
        self.declare()
        self.assertEqual(self.inventory().identities, frozenset())
        infrastructure = self.reserve(role="helper")
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()
        _, helper = self.actor(infrastructure)
        workload = self.reserve(kind="workload", role="unmanaged_baseline")
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()
        _, baseline = self.actor(workload)
        self.assertEqual(self.inventory().identities, frozenset((helper, baseline)))

    def test_pending_job_claim_blocks_until_exact_production_binding(self):
        guardian, _ = self.actor(role="guardian")
        wrapper, _ = self.actor(role="wrapper")
        member = self.reserve(kind="workload", role="workload")
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()
        execution, nonce = str(uuid4()), uuid4().hex
        binding = host.JobBinding(member.member_id, "managed",
            "Local\\ResourceSentinel.Job." + execution + "." + nonce, nonce,
            guardian.member_id, wrapper.member_id, execution, uuid4().hex)
        with self.locked() as (conn, guard):
            host.publish_job_locked(conn, scope=self.scope_owner, binding=binding, policy=self.policy, guard=guard)
            conn.commit()
        self.assertEqual(self.inventory().managed_job_names, (binding.job_name,))

    def test_query_only_binding_is_not_a_managed_execution_and_does_not_spend_managed_slots(self):
        query_owner, _ = self.actor(role="query_owner")
        for _ in range(3):
            self.job(kind="query_only", guardian=query_owner)
        self.job()
        inventory = self.inventory()
        self.assertEqual((len(inventory.managed_job_names), len(inventory.query_job_names)), (1, 3))
        for row in self.rows(host.JOBS_TABLE):
            if row["kind"] == "query_only":
                self.assertIsNone(row["isolated_execution_id"])
                self.assertIsNone(row["isolated_reservation_id"])
                self.assertIsNone(row["wrapper_member_id"])
        self.assertEqual(len(self.rows("managed_executions")), 1)

    def test_actual_ten_managed_and_forty_query_jobs_share_one_aggregate_and_stop_at_each_cap(self):
        guardian, _ = self.actor(role="guardian")
        query_owner, _ = self.actor(role="query_owner")
        for _ in range(10):
            self.job(guardian=guardian)
        for _ in range(40):
            self.job(kind="query_only", guardian=query_owner)
        inventory = self.inventory()
        self.assertEqual((len(inventory.managed_job_names), len(inventory.query_job_names)), (10, 40))
        self.assertEqual(len(self.rows(host.JOBS_TABLE)), 50)
        self.assertEqual(len(self.rows("reservations")), 1)
        self.assertEqual(len(self.rows("managed_executions")), 1)
        before = self.rows(host.JOBS_TABLE)
        with self.assertRaisesRegex(RuntimeError, "job_limit"):
            self.job(guardian=guardian)
        with self.assertRaisesRegex(host.HostLedgerError, "job_limit_or_duplicate"):
            self.job(kind="query_only", guardian=query_owner)
        self.assertEqual(self.rows(host.JOBS_TABLE), before)
        # The unsuccessful publications leave their immutable creation claims
        # pending; they cannot release capacity or let legacy writers through.
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()
        self.fixture.assert_retained(self.owner)

    def test_ordinary_production_and_host_managed_jobs_share_the_ten_job_limit(self):
        for _ in range(9):
            self.production_job()
        self.job()
        self.assertEqual(len(self.inventory().managed_job_names), 1)
        with self.assertRaisesRegex(RuntimeError, "job_limit"):
            self.job()
        self.assertEqual(len(self.rows(host.JOBS_TABLE)), 1)
        self.assertEqual(len(self.rows("reservations")), 10)

    def test_existing_s1_and_ordinary_jobs_are_counted_before_prospective_host_job(self):
        # S1 and a new root experiment cannot both be active. Exercise their
        # shared count at the prospective-host boundary without weakening that
        # serial-experiment invariant or broadening the S1 binding grammar.
        fixture = exclusion_fixtures.ExperimentExclusionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        for _ in range(8):
            fixture._production_job()
        fixture.register()
        name = "Local\\ResourceSentinel.Job." + str(uuid4()) + "." + uuid4().hex
        query = tuple("Local\\ResourceSentinel.Test.Job." + uuid4().hex for _ in range(40))
        with fixture.locked() as (conn, guard):
            history = host.experiment_history.verify_experiment_history_locked(conn)
            host._combined_jobs(conn, history, (name,), query)
        fixture._production_job()
        with fixture.locked() as (conn, guard):
            history = host.experiment_history.verify_experiment_history_locked(conn)
            with self.assertRaisesRegex(RuntimeError, "job_limit"):
                host._combined_jobs(conn, history, (name,), query)

    def test_s2_cannot_register_query_only_scope(self):
        other = ExperimentHostLedgerTests()
        other.SUITE = "S2"
        other.setUp()
        self.addCleanup(other.doCleanups)
        with self.assertRaisesRegex(host.HostLedgerError, "query_scope_invalid"):
            other.job(kind="query_only")
        self.assertEqual(other.rows(host.JOBS_TABLE), [])

    def test_floor_and_published_exclusions_survive_hold_but_new_claims_stop(self):
        job = self.job()
        conn = self.connection()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',"
            "hold_reason='reservation_expired',state_revision=state_revision+1 WHERE execution_id=?",
            (self.owner._snapshot.execution_id,))
        self.assertEqual(self.inventory().managed_job_names, (job.job_name,))
        with self.assertRaisesRegex(host.HostLedgerError, "no_new_work"):
            self.reserve()
        self.fixture.assert_retained(self.owner)

    def test_committed_original_reconciliation_survives_hold_without_new_publication(self):
        claim, identity = self.actor()
        job = self.job()
        original_scope = self.scope_owner
        conn = self.connection()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',"
            "hold_reason='reservation_expired',state_revision=state_revision+1 WHERE execution_id=?",
            (self.owner._snapshot.execution_id,))
        before = {table: self.rows(table) for table in (*host.TABLES, "reservations", "managed_executions")}
        revision = self.revision()
        self.assertIs(self.declare(), original_scope)
        self.reserve(claim=claim)
        self.actor(claim, identity=identity)
        with self.locked() as (conn, guard):
            host.publish_job_locked(conn, scope=original_scope, binding=job, policy=self.policy, guard=guard)
        with self.assertRaisesRegex(host.HostLedgerError, "no_new_work"):
            self.reserve()
        self.assertEqual(self.revision(), revision)
        self.assertEqual({table: self.rows(table) for table in before}, before)

    def test_exact_original_replay_survives_sql_expiry_or_draining_but_new_claim_does_not(self):
        claim, identity = self.actor()
        expiration = self.rows("reservations")[0]["expires_at"]
        before = {table: self.rows(table) for table in (*host.TABLES, "reservations", "managed_executions")}
        revision = self.revision()
        for condition in ("expired", "draining"):
            with self.subTest(condition=condition), self.locked() as (conn, guard):
                if condition == "expired":
                    conn.create_function("julianday", 1, lambda value: (expiration + 1) / 86400 + 2440587.5)
                else:
                    self.fixture.generation["state"] = "DRAINING"
                try:
                    self.assertIs(host.declare_scope_locked(conn, demand=self.owner, spec=self.spec,
                        policy=self.policy, guard=guard), self.scope_owner)
                    host.reserve_member_locked(conn, scope=self.scope_owner, claim=claim,
                        policy=self.policy, guard=guard)
                    host.publish_actor_locked(conn, scope=self.scope_owner, member_id=claim.member_id,
                        actor=identity, policy=self.policy, guard=guard)
                    new = host.MemberClaim(str(uuid4()), "infrastructure", "helper", ResourceDemand(.001, MIB, MIB, 0))
                    with self.assertRaisesRegex(host.HostLedgerError, "no_new_work"):
                        host.reserve_member_locked(conn, scope=self.scope_owner, claim=new,
                            policy=self.policy, guard=guard)
                finally:
                    self.fixture.generation["state"] = "ACTIVE"
        self.assertEqual(self.revision(), revision)
        self.assertEqual({table: self.rows(table) for table in before}, before)

    def test_sql_clock_expiry_does_not_drop_observations_or_renew_allocation(self):
        job = self.job()
        source = self.rows("reservations")[0]
        with self.locked() as (conn, guard):
            conn.create_function("julianday", 1, lambda value: (source["expires_at"] + 1) / 86400 + 2440587.5)
            self.assertEqual(host.read_locked(conn, policy=self.policy, guard=guard).managed_job_names, (job.job_name,))
            claim = host.MemberClaim(str(uuid4()), "infrastructure", "helper", ResourceDemand(.001, MIB, MIB, 0))
            with self.assertRaisesRegex(host.HostLedgerError, "no_new_work"):
                host.reserve_member_locked(conn, scope=self.scope_owner, claim=claim, policy=self.policy, guard=guard)
        self.assertEqual(self.rows("reservations"), [source])

    def test_host_scope_blocks_old_daily_completion_even_with_old_release_udf(self):
        self.declare()
        original = self.rows("managed_executions")[0]
        with self.locked() as (conn, guard):
            with self.assertRaisesRegex(host.HostLedgerError, "cleanup_unverified"):
                host.assert_release_unblocked_locked(conn, experiment_id=self.owner.declaration.experiment_id,
                    execution_id=self.owner._snapshot.execution_id, reservation_id=self.admitted["reservation_id"])
            conn.create_function("sentinel_experiment_release_mutation", -1, lambda *args: 1)
            with self.assertRaisesRegex(sqlite3.IntegrityError, "experiment_host_cleanup_unverified"):
                conn.execute("DELETE FROM reservations WHERE id=?", (self.admitted["reservation_id"],))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "experiment_host_cleanup_unverified"):
                conn.execute("UPDATE managed_executions SET state='CANCELLED_BEFORE_START',"
                    "launch_sealed=1,claim_consumed=1 WHERE execution_id=?", (self.owner._snapshot.execution_id,))
        self.assertEqual(self.rows("managed_executions"), [original])
        self.fixture.assert_retained(self.owner)

    def test_secondary_unique_replace_cannot_destroy_actor_history_with_recursive_triggers_off(self):
        claim, _ = self.actor()
        original = self.rows(host.ACTORS_TABLE)[0]
        conn = self.connection()
        conn.execute("PRAGMA recursive_triggers=OFF")
        fields = host.FIELDS[host.ACTORS_TABLE]
        replacement = dict(original, member_id=str(uuid4()))
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("INSERT OR REPLACE INTO " + host.ACTORS_TABLE + "(" + ",".join(fields) +
                ") VALUES(" + ",".join("?" for _ in fields) + ")", tuple(replacement[key] for key in fields))
        self.assertEqual(self.rows(host.ACTORS_TABLE), [original])
        self.assertEqual(self.rows(host.ACTORS_TABLE)[0]["member_id"], claim.member_id)

    def test_raw_first_inserts_with_valid_digests_cannot_clear_pending_publication(self):
        pending = self.reserve(role="helper")
        identity = ProcessIdentity(9876, self.owner._snapshot.wrapper_identity.created_filetime_100ns + 9876, self.logon)
        revision = self.revision()
        actor = host._new_row(dict(member_id=pending.member_id, scope_id=self.spec.scope_id,
                                  identity_json=host._canonical(identity.to_dict())), revision)
        member = host._new_row(dict(member_id=str(uuid4()), scope_id=self.spec.scope_id,
            kind="infrastructure", role="observer", demand_json=host._canonical(ResourceDemand(.001, MIB, MIB, 0).to_dict())), revision)
        def raw_insert(conn, table, row):
            fields = host.FIELDS[table]
            conn.execute("INSERT INTO " + table + "(" + ",".join(fields) + ") VALUES(" +
                         ",".join("?" for _ in fields) + ")", tuple(row[key] for key in fields))
        for table, row in ((host.MEMBERS_TABLE, member), (host.ACTORS_TABLE, actor)):
            with self.subTest(table=table), self.locked() as (conn, guard):
                with self.assertRaises(sqlite3.DatabaseError):
                    raw_insert(conn, table, row)
                conn.commit()
        self.assertEqual(self.revision(), revision)
        self.assertEqual(self.rows(host.ACTORS_TABLE), [])
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()
        # Same exact connection after the legitimate lexical publication has
        # returned must no longer possess its INSERT capability.
        with self.locked() as (conn, guard):
            host.publish_actor_locked(conn, scope=self.scope_owner, member_id=pending.member_id,
                                      actor=identity, policy=self.policy, guard=guard)
            with self.assertRaises(sqlite3.DatabaseError):
                raw_insert(conn, host.MEMBERS_TABLE, member)
            conn.commit()
        self.assertEqual(self.inventory().identities, frozenset({identity}))
        self.assertEqual(len(self.rows(host.MEMBERS_TABLE)), 1)

    def test_same_identity_cannot_claim_two_infrastructure_budgets(self):
        first, identity = self.actor()
        second = self.reserve()
        with self.assertRaises(sqlite3.IntegrityError):
            self.actor(second, identity=identity)
        self.assertEqual(len(self.rows(host.ACTORS_TABLE)), 1)
        with self.assertRaisesRegex(host.HostLedgerError, "member_publication_pending"):
            self.inventory()

    def test_copy_of_claim_or_scope_is_not_an_idempotent_original_operation(self):
        claim, identity = self.actor()
        revision = self.revision()
        self.reserve(claim=claim)
        self.actor(claim, identity=identity)
        self.assertEqual(self.revision(), revision)
        with self.assertRaisesRegex(host.HostLedgerError, "original_publication_changed"):
            self.reserve(claim=replace(claim))
        with self.assertRaisesRegex(host.HostLedgerError, "original_scope_required"):
            host.RegisteredHostScope(self.owner, self.spec, {})

    def test_transaction_has_no_path_or_native_readiness_calls(self):
        self.declare()
        claim = host.MemberClaim(str(uuid4()), "infrastructure", "helper", ResourceDemand(.001, MIB, MIB, 0))
        with self.locked() as (conn, guard):
            with patch.object(Path, "stat", side_effect=AssertionError("filesystem in SQL")), \
                    patch.object(Path, "resolve", side_effect=AssertionError("path resolution in SQL")), \
                    patch.object(self.fixture.proof, "prepare_connection", side_effect=AssertionError("readiness in SQL")):
                host.reserve_member_locked(conn, scope=self.scope_owner, claim=claim, policy=self.policy, guard=guard)
            conn.commit()
        self.assertEqual(len(self.rows(host.MEMBERS_TABLE)), 1)


if __name__ == "__main__":
    unittest.main()
