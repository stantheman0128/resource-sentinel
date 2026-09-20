"""L1 legacy-writer integration against real, isolated policy/grant ledgers.

All process/Job operations below are explicit synthetic factories. These tests
exercise execute_batch, not Windows setters or production readiness. Existing
lifecycle helpers create real RESERVED rows using their explicit L1 provider;
synthetic Job metadata is identified as such and proves no native containment.
"""
from contextlib import closing, contextmanager, redirect_stdout
from dataclasses import replace
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.exemption_sync import bind_policy_locked, commit_grant_locked
from sentinel.adaptive import exemption_sync
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive import legacy_writer as writer
from sentinel.adaptive.policy import PolicyError
from tests import test_adaptive_lifecycle as lifecycle_fixtures

NOW, WRAPPER = lifecycle_fixtures.NOW, lifecycle_fixtures.WRAPPER


class SyntheticClock:
    def __init__(self):
        self.value = 10.0

    def __call__(self):
        return self.value


class SyntheticTarget:
    """A retained test object; never opens or changes a real process."""
    def __init__(self, owner, identity, *, priority="Normal", alive=True,
                 member=False, close_failure=False):
        self.owner, self.identity = owner, identity
        self.current_priority, self.live, self.member = priority, alive, member
        self.close_failure = close_failure
        self.closed = False
        self.calls = []
        self.on_set_priority = None
        self.on_priority = None
        self.on_membership = None
        self.on_alive = None
        self.readback_mismatch = False

    def require_open(self):
        if self.closed:
            raise AssertionError("fixture_target_already_closed")

    def alive(self):
        self.require_open()
        self.calls.append("alive")
        if self.on_alive is not None:
            self.on_alive()
        return self.live

    def is_in_job(self, job):
        self.require_open()
        if job.closed:
            raise AssertionError("fixture_job_already_closed")
        self.owner.assert_native_scope()
        self.calls.append(("membership", job.name))
        if self.on_membership is not None:
            self.on_membership()
        if isinstance(self.member, BaseException):
            raise self.member
        return self.member.get(job.name, False) if isinstance(self.member, dict) else self.member

    def priority(self):
        self.require_open()
        self.owner.assert_native_scope()
        self.calls.append("priority")
        if self.on_priority is not None:
            self.on_priority()
        return self.current_priority

    def set_priority(self, value):
        self.require_open()
        self.owner.assert_native_scope()
        self.calls.append(("set_priority", value))
        self.owner.writes.append((self.identity, "priority", value))
        if not self.readback_mismatch:
            self.current_priority = value
        if self.on_set_priority is not None:
            self.on_set_priority()

    def set_io_priority(self, value):
        self.require_open()
        self.owner.assert_native_scope()
        self.calls.append(("set_io", value))
        self.owner.writes.append((self.identity, "io", value))

    def trim(self):
        self.require_open()
        self.owner.assert_native_scope()
        self.calls.append("trim")
        self.owner.writes.append((self.identity, "trim", True))

    def close(self):
        self.calls.append(("close", self.owner.policy.active))
        if self.close_failure:
            raise RuntimeError("fixture_process_cleanup_uncertain")
        self.closed = True


class SyntheticJob:
    def __init__(self, owner, name, *, close_failure=False):
        self.owner, self.name = owner, name
        self.close_failure, self.closed = close_failure, False

    def close(self):
        self.owner.assert_native_scope()
        if self.close_failure:
            raise RuntimeError("fixture_job_cleanup_uncertain")
        self.closed = True


class SyntheticIdentityBackend:
    """VerifiedProcess test backend, not a fabricated serialized observation."""
    def __init__(self, status=IdentityStatus.ALIVE):
        self.status, self.closed = status, []

    def wait(self, handle):
        if self.status is IdentityStatus.UNKNOWN:
            raise IdentityUnavailable("fixture_identity_unknown")
        return self.status

    def close(self, handle):
        self.closed.append(handle)


class LegacyWriterTests(unittest.TestCase):
    # Reuse fixture setup/helper methods only; do not inherit its test cases.
    connection = lifecycle_fixtures.AdaptiveLifecycleTests.connection
    spec = lifecycle_fixtures.AdaptiveLifecycleTests.spec
    allocate = lifecycle_fixtures.AdaptiveLifecycleTests.allocate
    registered = lifecycle_fixtures.AdaptiveLifecycleTests.registered

    def setUp(self):
        lifecycle_fixtures.AdaptiveLifecycleTests.setUp(self)
        self.exemptions = SimpleNamespace(path=self.directory / "exemptions.sqlite3")
        self.clock = SyntheticClock()
        self.targets, self.jobs = {}, {}
        self.writes, self.opens, self.job_opens = [], [], []
        with self.held():
            writer.initialize_registry_locked(self.store)
            bind_policy_locked(self.exemptions, self.store)

    @contextmanager
    def held(self):
        guard = self.store._policy.prepare(WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            yield guard

    def assert_native_scope(self):
        self.assertTrue(self.policy.active)
        self.assertIsNotNone(self.store._policy.current_guard())
        # Successful independent writer acquisition proves no DB writer lock
        # remains held across a setter/query/Job-close callback.
        for path in (self.db, self.exemptions.path):
            with closing(sqlite3.connect(path, timeout=0, isolation_level=None)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()

    def runtime(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def identity(self, pid=501, *, birth=134342315823996150):
        return ProcessIdentity(pid, birth, WRAPPER.logon_id)

    def candidate(self, pid=501, *, identity=None, action="demote", io_priority=1, trim=True):
        return writer.Candidate(identity or self.identity(pid), action, "Normal", io_priority, trim)

    def target(self, identity=None, **kwargs):
        identity = self.identity() if identity is None else identity
        result = SyntheticTarget(self, identity, **kwargs)
        self.targets[identity.pid] = result
        return result

    def process_factory(self, identity, *, operations):
        self.assertFalse(self.policy.active)
        self.opens.append((identity, operations))
        existing = self.targets.get(identity.pid)
        if existing is not None and existing.closed:
            self.targets[identity.pid] = SyntheticTarget(self, identity,
                priority=existing.current_priority, alive=existing.live, member=existing.member)
        return self.targets.setdefault(identity.pid, SyntheticTarget(self, identity))

    def job_factory(self, name, logon):
        self.assert_native_scope()
        self.assertEqual(logon, WRAPPER.logon_id)
        self.job_opens.append(name)
        if name in self.jobs and self.jobs[name].closed:
            self.jobs[name] = SyntheticJob(self, name)
        return self.jobs.setdefault(name, SyntheticJob(self, name))

    def execute(self, candidates, **kwargs):
        return writer.execute_batch(self.store, self.exemptions, candidates,
            process_factory=kwargs.pop("process_factory", self.process_factory),
            job_factory=kwargs.pop("job_factory", self.job_factory),
            clock=self.clock, wall_clock=lambda: NOW, **kwargs)

    def synthetic_job_row(self, *, wrapper=None, state="RUNNING"):
        spec, _ = self.registered(self.spec(wrapper=wrapper or WRAPPER))
        nonce = uuid4().hex
        name = f"Local\\ResourceSentinel.Job.{spec.execution_id}.{nonce}"
        # Synthetic registry fixture only. No native Job or containment is
        # asserted; execute_batch must use its injected retained Job query.
        self.connection().execute("""UPDATE managed_executions
            SET state=?,job_name=?,job_nonce=? WHERE execution_id=?""",
            (state, name, nonce, spec.execution_id))
        return spec, name

    def grant(self):
        row = dict(id=uuid4().hex, root_pid=4000000000, root_started=123.5,
                   created_at=NOW, expires_at=NOW + 3600,
                   reason="explicit isolated fixture authorization", revoked_at=None)
        with self.held():
            return commit_grant_locked(self.exemptions, row, lifecycle_store=self.store, now=NOW)

    def verified_process(self, identity, status=IdentityStatus.ALIVE):
        backend = SyntheticIdentityBackend(status)
        process = VerifiedProcess(backend, identity.pid + 10000, identity)
        self.addCleanup(process.close)
        return process, backend

    def test_actual_batch_sets_unmanaged_target_under_policy_without_database_writer_lock(self):
        candidate = self.candidate()
        target = self.target()
        result = self.execute([candidate])
        self.assertTrue(result["available"])
        self.assertEqual(result["reason"], "ok")
        self.assertEqual(self.writes, [(candidate.identity, "priority", "BelowNormal"),
                                      (candidate.identity, "io", 1), (candidate.identity, "trim", True)])
        row = result["results"][0]
        self.assertEqual((row["status"], row["priority_before"], row["priority_after"], row["io_applied"], row["trim_applied"]),
                         ("applied", "Normal", "BelowNormal", 1, True))
        self.assertEqual(self.opens, [(candidate.identity, frozenset({"priority", "io_priority", "trim"}))])
        self.assertTrue(target.closed)
        self.assertIn(("close", True), target.calls)
        self.assertFalse(self.policy.active)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_reserved_wrapper_excludes_constraints_and_legacy_restore_before_any_job_exists(self):
        spec, _ = self.registered()
        for action in ("demote", "restore"):
            with self.subTest(action=action):
                self.target(spec.wrapper_identity, priority="BelowNormal" if action == "restore" else "Normal")
                result = self.execute([self.candidate(identity=spec.wrapper_identity, action=action, io_priority=2)])
                self.assertEqual(result["results"][0]["reason"], "legacy_managed_scope")
                self.assertEqual(result["results"][0]["status"], "skipped")
        self.assertEqual(self.writes, [])
        self.assertEqual(self.job_opens, [])

    def test_job_members_excluded_from_all_writers_even_off_or_recovery_hold(self):
        _, name = self.synthetic_job_row()
        for mode, barrier in (("off", "NONE"), ("shadow", "NONE"), ("off", "RECOVERY_HOLD")):
            self.connection().execute("UPDATE adaptive_runtime SET mode=?,admission_barrier=? WHERE singleton=1", (mode, barrier))
            for action, io_priority in (("demote", 1), ("restore", 2)):
                with self.subTest(mode=mode, barrier=barrier, action=action):
                    target = self.target(priority="BelowNormal", member={name: True})
                    result = self.execute([self.candidate(action=action, io_priority=io_priority)])
                    self.assertTrue(result["available"])
                    self.assertEqual(result["results"][0]["reason"], "legacy_managed_scope")
                    self.assertIn(("membership", name), target.calls)
        self.assertEqual(self.writes, [])
        self.assertTrue(all(job.closed for job in self.jobs.values()))

    def test_missing_infrastructure_registry_blocks_every_writer(self):
        self.connection().execute("DROP TABLE adaptive_infrastructure")
        result = self.execute([self.candidate()])
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])
        self.assertTrue(self.targets[501].closed)

    def test_missing_managed_registry_blocks_every_writer(self):
        self.connection().execute("DROP TABLE managed_executions")
        result = self.execute([self.candidate()])
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])

    def test_missing_bound_grant_database_is_unavailable_not_empty(self):
        self.exemptions.path.unlink()
        result = self.execute([self.candidate()])
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])
        self.assertFalse(self.exemptions.path.exists())

    def test_corrupt_revocation_is_not_interpreted_as_no_active_grant(self):
        grant = self.grant()
        with closing(sqlite3.connect(self.exemptions.path, isolation_level=None)) as conn:
            conn.execute("""UPDATE exemptions SET revoked_at='unknown',writer_protocol=1,
                writer_revision=writer_revision+1 WHERE id=?""", (grant["id"],))
        result = self.execute([self.candidate()])
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])

    def test_missing_job_with_running_unknown_consumed_or_inflight_launch_blocks_all_candidates(self):
        spec, _ = self.registered()
        for state, consumed, inflight in (("RUNNING", 0, 0), ("START_UNKNOWN", 0, 0),
                                           ("RESERVED", 1, 0), ("RESERVED", 0, 1)):
            with self.subTest(state=state, consumed=consumed, inflight=inflight):
                self.connection().execute("""UPDATE managed_executions SET state=?,
                    claim_consumed=?,launch_in_flight=? WHERE execution_id=?""",
                    (state, consumed, inflight, spec.execution_id))
                result = self.execute([self.candidate()])
                self.assertFalse(result["available"])
                self.assertEqual(self.writes, [])
                self.assertEqual(self.job_opens, [])

    def test_terminal_label_with_inflight_or_unsealed_launch_remains_fail_closed(self):
        spec, _ = self.registered()
        for sealed, inflight in ((1, 1), (0, 0)):
            with self.subTest(sealed=sealed, inflight=inflight):
                self.connection().execute("""UPDATE managed_executions SET state='FINISHED',
                    launch_sealed=?,launch_in_flight=? WHERE execution_id=?""", (sealed, inflight, spec.execution_id))
                result = self.execute([self.candidate()])
                self.assertFalse(result["available"])
                self.assertEqual(self.writes, [])
                self.assertEqual(self.job_opens, [])

    def test_missing_named_job_is_not_treated_as_an_empty_job(self):
        self.synthetic_job_row()
        factory = Mock(side_effect=RuntimeError("fixture_job_missing"))
        result = self.execute([self.candidate()], job_factory=factory)
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])
        factory.assert_called_once()

    def test_unknown_or_nonboolean_membership_never_authorizes_a_set(self):
        self.synthetic_job_row()
        for member in (None, 1):
            with self.subTest(member=member):
                self.target(member=member)
                result = self.execute([self.candidate()])
                self.assertEqual(result["results"][0]["reason"], "legacy_membership_unknown")
        self.assertEqual(self.writes, [])

    def test_dead_or_unknown_candidate_is_never_written(self):
        for alive in (None, False):
            with self.subTest(alive=alive):
                self.target(alive=alive)
                result = self.execute([self.candidate()])
                self.assertEqual(result["results"][0]["reason"], "legacy_identity_unavailable")
        self.assertEqual(self.writes, [])

    def test_process_open_failure_does_not_authorize_fallback_pid_writes(self):
        result = self.execute([self.candidate()], process_factory=Mock(side_effect=RuntimeError("fixture_access_denied")))
        self.assertEqual(result["results"][0]["reason"], "legacy_identity_unavailable")
        self.assertEqual(self.writes, [])

    def test_a_single_filetime_tick_mismatch_rejects_the_opened_target(self):
        expected = self.identity()
        target = self.target(replace(expected, created_filetime_100ns=expected.created_filetime_100ns + 1))
        result = self.execute([self.candidate(identity=expected)])
        self.assertEqual(result["results"][0]["reason"], "legacy_identity_unavailable")
        self.assertTrue(target.closed)
        self.assertEqual(self.writes, [])

    def test_old_reserved_identity_does_not_turn_reused_pid_into_a_managed_identity(self):
        spec, _ = self.registered()
        reused = replace(spec.wrapper_identity, created_filetime_100ns=spec.wrapper_identity.created_filetime_100ns + 1)
        self.target(reused)
        result = self.execute([self.candidate(identity=reused, io_priority=None, trim=False)])
        self.assertEqual(result["results"][0]["created_filetime_100ns"], str(reused.created_filetime_100ns))
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertEqual(self.writes, [(reused, "priority", "BelowNormal")])

    def test_deadline_after_first_set_prevents_io_trim_and_next_candidate_set(self):
        first, second = self.candidate(), self.candidate(502)
        target = self.target(first.identity)
        self.target(second.identity)
        target.on_set_priority = lambda: setattr(self.clock, "value", self.clock.value + .251)
        result = self.execute([first, second])
        self.assertEqual(self.writes, [(first.identity, "priority", "BelowNormal")])
        self.assertEqual([row["reason"] for row in result["results"]],
                         ["legacy_batch_budget_exhausted", "legacy_batch_budget_exhausted"])
        # Readback/cleanup of the already attempted Set are not new setters.
        self.assertTrue(all(target.closed for target in self.targets.values()))

    def test_deadline_during_priority_query_prevents_even_the_first_set(self):
        target = self.target()
        target.on_priority = lambda: setattr(self.clock, "value", self.clock.value + .251)
        result = self.execute([self.candidate()])
        self.assertEqual(result["results"][0]["reason"], "legacy_batch_budget_exhausted")
        self.assertEqual(self.writes, [])

    def test_deadline_during_membership_prevents_all_setters(self):
        self.synthetic_job_row()
        target = self.target()
        target.on_membership = lambda: setattr(self.clock, "value", self.clock.value + .251)
        result = self.execute([self.candidate()])
        self.assertEqual(result["results"][0]["reason"], "legacy_batch_budget_exhausted")
        self.assertEqual(self.writes, [])

    def test_same_deadline_reaches_both_grant_reads_without_resetting_sqlite_waits(self):
        registry = writer._registry_locked
        budget = exemption_sync._read_budget
        connect = exemption_sync._connect
        observed_budgets, connections = [], []
        deadline = self.clock.value + writer.BATCH_SECONDS

        def slow_registry(*args, **kwargs):
            result = registry(*args, **kwargs)
            self.clock.value += .238
            return result

        def observe_budget(conn, shared_deadline, clock):
            budget(conn, shared_deadline, clock)
            observed_budgets.append((shared_deadline, conn.execute("PRAGMA busy_timeout").fetchone()[0]))
            if len(observed_budgets) == 1:
                self.clock.value += .007  # first grant-ledger validation consumed seven more ms

        def observe_connect(path, **kwargs):
            connections.append((Path(path), kwargs.get("timeout")))
            return connect(path, **kwargs)

        with patch.object(writer, "_registry_locked", side_effect=slow_registry), \
                patch.object(exemption_sync, "_read_budget", side_effect=observe_budget), \
                patch.object(exemption_sync, "_connect", side_effect=observe_connect):
            result = self.execute([self.candidate()])
        self.assertTrue(result["available"])
        self.assertEqual(len(observed_budgets), 2)
        self.assertTrue(all(value == deadline for value, _ in observed_budgets))
        waits = [wait for _, wait in observed_budgets]
        self.assertTrue(0 <= waits[1] < waits[0] <= 12, waits)
        self.assertEqual(connections, [(self.db.resolve(), 0), (self.exemptions.path.resolve(), 0)])

    def test_exhausted_registry_budget_never_opens_the_exemption_database(self):
        registry = writer._registry_locked
        def exhausted_registry(*args, **kwargs):
            result = registry(*args, **kwargs)
            self.clock.value += .251
            return result
        with patch.object(writer, "_registry_locked", side_effect=exhausted_registry), \
                patch.object(exemption_sync, "_connect") as connect:
            result = self.execute([self.candidate()])
        connect.assert_not_called()
        self.assertFalse(result["available"])
        self.assertEqual(self.writes, [])

    def test_identity_loss_during_ready_is_reported_and_prevents_setters(self):
        target = self.target()
        observations = []
        def lose_identity():
            observations.append(True)
            if len(observations) == 2:
                target.live = None
        target.on_alive = lose_identity
        result = self.execute([self.candidate()])
        self.assertEqual(result["results"][0]["status"], "skipped")
        self.assertEqual(result["results"][0]["reason"], "legacy_identity_unavailable")
        self.assertEqual(self.writes, [])

    def test_active_unverifiable_grant_suppresses_constraints_but_allows_unmanaged_restore(self):
        self.grant()
        limited, restoring = self.candidate(), self.candidate(502, action="restore", io_priority=2, trim=False)
        self.target(limited.identity)
        self.target(restoring.identity, priority="BelowNormal")
        result = self.execute([limited, restoring])
        self.assertEqual(result["results"][0]["reason"], "exemption_scope_unresolved")
        self.assertEqual(result["results"][0]["status"], "skipped")
        self.assertEqual(result["results"][1]["status"], "applied")
        self.assertEqual(self.writes, [(restoring.identity, "priority", "Normal"), (restoring.identity, "io", 2)])

    def test_active_grant_blocks_restore_to_idle_because_it_is_a_constraint(self):
        self.grant()
        candidate = replace(self.candidate(action="restore", io_priority=None, trim=False), restore_priority="Idle")
        self.target(priority="BelowNormal")
        result = self.execute([candidate])
        self.assertEqual(result["results"][0]["reason"], "exemption_scope_unresolved")
        self.assertEqual(result["results"][0]["status"], "skipped")
        self.assertEqual(self.writes, [])

    def test_active_grant_allows_restore_but_keeps_trim_skipped_in_the_same_candidate(self):
        self.grant()
        candidate = self.candidate(action="restore", io_priority=None, trim=True)
        self.target(priority="BelowNormal")
        result = self.execute([candidate])
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertEqual(result["results"][0]["reason"], "exemption_scope_unresolved")
        self.assertFalse(result["results"][0]["trim_applied"])
        self.assertEqual(self.writes, [(candidate.identity, "priority", "Normal")])

    def test_priority_readback_mismatch_is_partial_and_does_not_continue_other_writes(self):
        self.target().readback_mismatch = True
        result = self.execute([self.candidate()])
        self.assertEqual(result["results"][0]["status"], "partial")
        self.assertEqual(result["results"][0]["reason"], "legacy_mutation_unverified")
        self.assertIsNone(result["results"][0]["priority_after"])
        self.assertEqual(len(self.writes), 1)

    def test_process_cleanup_failure_cannot_return_success_and_retains_policy_uncertainty(self):
        target = self.target(close_failure=True)
        with self.assertRaisesRegex(RuntimeError, "fixture_process_cleanup_uncertain"):
            self.execute([self.candidate()])
        self.assertEqual(len(self.writes), 3)
        self.assertIn(("close", True), target.calls)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_job_cleanup_failure_cannot_return_success(self):
        _, name = self.synthetic_job_row()
        self.jobs[name] = SyntheticJob(self, name, close_failure=True)
        with self.assertRaisesRegex(RuntimeError, "fixture_job_cleanup_uncertain"):
            self.execute([self.candidate()])
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertTrue(self.targets[501].closed)
        self.assertIn(("close", True), self.targets[501].calls)

    def test_policy_release_failure_cannot_acknowledge_already_attempted_writes(self):
        hold = self.policy.hold
        @contextmanager
        def uncertain_release(binding, *, timeout_ms=250):
            with hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise RuntimeError("fixture_policy_release_uncertain")
        target = self.target()
        with patch.object(self.policy, "hold", uncertain_release):
            with self.assertRaisesRegex(RuntimeError, "fixture_policy_release_uncertain"):
                self.execute([self.candidate()])
        self.assertEqual(len(self.writes), 3)
        self.assertTrue(target.closed)
        self.assertIn(("close", True), target.calls)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])

    def test_noted_open_cleanup_uncertainty_propagates_instead_of_becoming_identity_skip(self):
        error = RuntimeError("fixture_partial_open")
        error.add_note("fixture_handle_cleanup_unverified")
        with self.assertRaisesRegex(RuntimeError, "fixture_partial_open"):
            self.execute([self.candidate()], process_factory=Mock(side_effect=error))
        self.assertEqual(self.writes, [])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_candidate_bound_allows_256_and_rejects_257_before_opening_handles(self):
        candidates = [self.candidate(1000 + index, action="none", io_priority=None, trim=False) for index in range(256)]
        result = self.execute(candidates)
        self.assertTrue(result["available"])
        self.assertEqual(len(result["results"]), 256)
        self.assertEqual(len(self.opens), 256)
        self.assertEqual(self.writes, [])
        before = list(self.opens)
        with self.assertRaisesRegex(writer.LegacyMutationError, "legacy_batch_invalid"):
            self.execute(candidates + [self.candidate(2000)])
        self.assertEqual(self.opens, before)

    def test_duplicate_candidate_pid_with_different_birth_is_rejected_before_open(self):
        first = self.identity()
        second = replace(first, created_filetime_100ns=first.created_filetime_100ns + 1)
        with self.assertRaisesRegex(writer.LegacyMutationError, "legacy_batch_invalid"):
            self.execute([self.candidate(identity=first), self.candidate(identity=second)])
        self.assertEqual(self.opens, [])

    def test_ten_registered_jobs_are_queried_and_eleven_block_the_entire_batch(self):
        names = [self.synthetic_job_row()[1] for _ in range(10)]
        target = self.target()
        result = self.execute([self.candidate(io_priority=None, trim=False)])
        self.assertTrue(result["available"])
        self.assertEqual(set(self.job_opens), set(names))
        self.assertEqual({call[1] for call in target.calls if isinstance(call, tuple) and call[0] == "membership"}, set(names))
        self.assertEqual(len(self.writes), 1)
        self.synthetic_job_row()
        self.writes.clear()
        self.job_opens.clear()
        result = self.execute([self.candidate()])
        self.assertFalse(result["available"])
        self.assertEqual(self.job_opens, [])
        self.assertEqual(self.writes, [])

    def test_infrastructure_registration_uses_retained_identity_and_excludes_all_writers(self):
        identity = self.identity()
        process, _ = self.verified_process(identity)
        before = self.runtime()["registry_revision"]
        with self.held():
            self.assertTrue(writer.register_infrastructure_locked(self.store, "guardian", process))
            self.assertFalse(writer.register_infrastructure_locked(self.store, "guardian", process))
        self.assertEqual(self.runtime()["registry_revision"], before + 1)
        result = self.execute([self.candidate(identity=identity, action="restore", io_priority=2)])
        self.assertEqual(result["results"][0]["reason"], "legacy_managed_scope")
        self.assertEqual(self.writes, [])

    def test_infrastructure_registration_requires_current_policy_and_actual_verified_process(self):
        process, _ = self.verified_process(self.identity())
        with self.assertRaises(PolicyError):
            writer.register_infrastructure_locked(self.store, "helper", process)
        with self.held():
            with self.assertRaisesRegex(writer.LegacyMutationError, "identity_required"):
                writer.register_infrastructure_locked(self.store, "helper", SimpleNamespace(identity=self.identity()))

    def test_infrastructure_unknown_observation_cannot_register_or_remove_identity(self):
        process, backend = self.verified_process(self.identity())
        with self.held():
            writer.register_infrastructure_locked(self.store, "supervisor", process)
            backend.status = IdentityStatus.UNKNOWN
            with self.assertRaisesRegex(writer.LegacyMutationError, "identity_unverified"):
                writer.register_infrastructure_locked(self.store, "helper", process)
            with self.assertRaisesRegex(writer.LegacyMutationError, "death_unverified"):
                writer.unregister_dead_infrastructure_locked(self.store, "supervisor", process)
        result = self.execute([self.candidate()])
        self.assertEqual(result["results"][0]["reason"], "legacy_managed_scope")
        self.assertEqual(self.writes, [])

    def test_infrastructure_death_removal_is_exact_identity_and_idempotent(self):
        identity = self.identity()
        original, backend = self.verified_process(identity)
        reused, _ = self.verified_process(replace(identity, created_filetime_100ns=identity.created_filetime_100ns + 1), IdentityStatus.DEAD)
        with self.held():
            writer.register_infrastructure_locked(self.store, "guardian", original)
            revision = self.runtime()["registry_revision"]
            self.assertFalse(writer.unregister_dead_infrastructure_locked(self.store, "guardian", reused))
            with self.assertRaisesRegex(writer.LegacyMutationError, "death_unverified"):
                writer.unregister_dead_infrastructure_locked(self.store, "guardian", original)
            backend.status = IdentityStatus.DEAD
            self.assertTrue(writer.unregister_dead_infrastructure_locked(self.store, "guardian", original))
            self.assertFalse(writer.unregister_dead_infrastructure_locked(self.store, "guardian", original))
        self.assertEqual(self.runtime()["registry_revision"], revision + 1)

    def test_candidate_json_requires_decimal_filetime_without_float_rounding(self):
        value = dict(pid=501, created_filetime_100ns="134342315823996150",
                     priority_action="demote", restore_priority="Normal", io_priority=1, trim=True)
        candidate = writer.Candidate.from_dict(value, WRAPPER.logon_id)
        self.assertEqual(candidate.identity.created_filetime_100ns, 134342315823996150)
        with self.assertRaises(ValueError):
            writer.Candidate.from_dict(value | {"created_filetime_100ns": float(value["created_filetime_100ns"])}, WRAPPER.logon_id)

    def test_cli_missing_registry_returns_unavailable_without_creating_data_directory(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "legacy-mutation.py"
        spec = importlib.util.spec_from_file_location("sentinel_legacy_mutation_fixture", script)
        module = importlib.util.module_from_spec(spec)
        original_path = list(sys.path)
        try:
            spec.loader.exec_module(module)
        finally:
            sys.path[:] = original_path
        payload = self.directory / "legacy-input.json"
        payload.write_text(json.dumps({"protocol_version": 1, "candidates": [{
            "pid": 501, "created_filetime_100ns": "134342315823996150",
            "priority_action": "demote", "restore_priority": "Normal", "io_priority": 1, "trim": True}]}), encoding="utf-8")
        absent = self.directory / "does-not-exist"
        output = io.StringIO()
        with patch("sentinel.adaptive.policy.NativePolicyProvider.current_logon") as native, redirect_stdout(output):
            code = module.main(["--data-dir", str(absent), "--input", str(payload)])
        native.assert_not_called()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue()), {"protocol_version": 1, "available": False,
                         "reason": "legacy_batch_unavailable", "results": []})
        self.assertFalse(absent.exists())


if __name__ == "__main__":
    unittest.main()
