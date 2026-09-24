"""Original launch restrictions with actual SQL and explicit synthetic native I/O.

The launcher, original scope factory, allocation validation and journal execute
their real code. Native kernels, readiness and transport are portable fixtures;
these cases do not establish wrapper integration or native capability evidence.
"""
from contextlib import contextmanager
import hashlib
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_scope as scope
from sentinel.adaptive import native_launcher as native
from sentinel.adaptive import pipe_windows
from tests import test_adaptive_experiment_release_native as release_fixture
from tests import test_adaptive_native_launcher as launch_fixture
from tests.test_adaptive_coordinator import NOW
from tests.windows import adaptive_scope_launch as launch_module


class NativeLaunchBoundsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = launch_fixture.NativeLauncherTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.exchange_clock = SimpleNamespace(now=1000)
        self.exchange_clock.tick_ms = lambda: self.exchange_clock.now
        self.readiness_clock = SimpleNamespace(now=1000)
        self.readiness_clock.tick_ms = lambda: self.readiness_clock.now
        self.exchange = pipe_windows.NativeDeadline(self.exchange_clock, 1000, 5000,
            pipe_windows._DEADLINE_KEY)
        self.readiness = pipe_windows.NativeDeadline(self.readiness_clock, 1000, 1000,
            pipe_windows._DEADLINE_KEY)

    def bounds(self):
        return dict(native_deadline=self.exchange, readiness_deadline=self.readiness,
            scope_deadline_monotonic=120.0, lease_deadline_monotonic_ns=110_000_000_000,
            lease_expires_at=2000.0)

    def assert_not_entered(self, error):
        self.fixture.assert_no_create()
        owner = error.native_launch_owner
        self.assertTrue(owner.creation_definitely_absent)
        self.assertEqual(owner._creation_outcome, "not_attempted")
        self.assertEqual(self.fixture.calls("CloseHandle"),
            [("CloseHandle", handle) for handle in launch_fixture.STDIO_COPIES])
        self.assertEqual(len(self.fixture.calls("DeleteProcThreadAttributeList")), 1)
        owner.close()
        self.assertTrue(owner._closed)

    def test_readiness_requires_exact_original_deadline_before_effects(self):
        for value in (True, {}, object(), SimpleNamespace(require=lambda: 1000)):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "native_readiness_deadline_invalid"):
                self.fixture.launch(readiness_deadline=value)
        self.assertEqual(self.fixture.kernel.calls, [])
        self.assertEqual(self.fixture.identity.calls, [])

    def test_lease_requires_paired_strict_positive_finite_scalars_before_effects(self):
        cases = [(1, None), (None, 1), (True, 1), (1.0, 1), (0, 1), (-1, 1),
                 (1, True), (1, "2000"), (1, 0), (1, -1), (1, float("nan")), (1, float("inf"))]
        for monotonic_ns, wall in cases:
            with self.subTest(monotonic_ns=monotonic_ns, wall=wall), self.assertRaisesRegex(
                    ValueError, "native_lease_deadline_invalid"):
                self.fixture.launch(lease_deadline_monotonic_ns=monotonic_ns, lease_expires_at=wall)
        self.assertEqual(self.fixture.kernel.calls, [])
        self.assertEqual(self.fixture.identity.calls, [])

    def test_command_preparation_consumes_original_readiness_window(self):
        create_buffer = native.C.create_unicode_buffer
        def consume(*args, **kwargs):
            value = create_buffer(*args, **kwargs)
            self.readiness_clock.now = 2000
            return value
        with patch.object(native.C, "create_unicode_buffer", side_effect=consume), \
                self.assertRaises(pipe_windows.NativePipeError) as raised:
            self.fixture.launch(**self.bounds())
        self.assertGreater(self.exchange.require(), 0)
        self.assert_not_entered(raised.exception)

    def test_final_capture_consumes_exchange_even_while_readiness_is_current(self):
        clock = self.exchange_clock
        class Capture:
            cleanup_pending = False
            def capture(self, **kwargs):
                pass
            def confirm_launch(self):
                clock.now = 6000
        with self.assertRaises(pipe_windows.NativePipeError) as raised:
            self.fixture.launch(**self.bounds(), capture_factory=Capture)
        self.assertGreater(self.readiness.require(), 0)
        self.assert_not_entered(raised.exception)

    def test_backward_wall_jump_cannot_extend_frozen_monotonic_lease(self):
        clock = SimpleNamespace(monotonic_ns=100_000_000_000, wall=1900.0)
        class Capture:
            cleanup_pending = False
            def capture(self, **kwargs):
                pass
            def confirm_launch(self):
                clock.monotonic_ns, clock.wall = 110_000_000_000, 1000.0
        with patch.object(native.time, "monotonic", return_value=100.0), \
                patch.object(native.time, "monotonic_ns", side_effect=lambda: clock.monotonic_ns), \
                patch.object(native.time, "time", side_effect=lambda: clock.wall), \
                self.assertRaisesRegex(native.NativeLaunchError, "native_lease_deadline_expired") as raised:
            self.fixture.launch(**self.bounds(), capture_factory=Capture)
        self.assert_not_entered(raised.exception)

    def test_forward_wall_jump_refuses_even_before_monotonic_lease(self):
        clock = SimpleNamespace(wall=1900.0)
        class Capture:
            cleanup_pending = False
            def capture(self, **kwargs):
                pass
            def confirm_launch(self):
                clock.wall = 2000.0
        with patch.object(native.time, "monotonic", return_value=100.0), \
                patch.object(native.time, "monotonic_ns", return_value=100_000_000_000), \
                patch.object(native.time, "time", side_effect=lambda: clock.wall), \
                self.assertRaisesRegex(native.NativeLaunchError, "native_lease_deadline_expired") as raised:
            self.fixture.launch(**self.bounds(), capture_factory=Capture)
        self.assert_not_entered(raised.exception)

    def test_original_scope_cutoff_still_applies_with_both_current_deadlines(self):
        with patch.object(native.time, "monotonic", return_value=120.0), \
                self.assertRaisesRegex(native.NativeLaunchError, "native_scope_deadline_expired") as raised:
            self.fixture.launch(**self.bounds())
        self.assertGreater(self.exchange.require(), 0)
        self.assertGreater(self.readiness.require(), 0)
        self.assert_not_entered(raised.exception)

    def test_current_original_restrictions_create_once_without_new_deadline(self):
        before = (self.exchange._start, self.exchange._end, self.readiness._start, self.readiness._end)
        with patch.object(native.time, "monotonic", return_value=100.0), \
                patch.object(native.time, "monotonic_ns", return_value=100_000_000_000), \
                patch.object(native.time, "time", return_value=1900.0), \
                patch.object(pipe_windows.NativeDeadline, "after_ms", side_effect=AssertionError("deadline renewed")):
            owner = self.fixture.launch(**self.bounds())
        self.assertEqual(len(self.fixture.calls("CreateProcessW")), 1)
        self.assertEqual((self.exchange._start, self.exchange._end, self.readiness._start, self.readiness._end), before)
        owner.close()


class OriginalScopeLaunchBoundsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = release_fixture.ExperimentNativeReleaseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def prepared(self, *, lease_seconds=40):
        # Select this isolated fixture's actual policy before original capture
        # and admission. Published experiment allocations are immutable; they
        # do not support an ordinary heartbeat/expiry UPDATE afterward.
        config_path = self.fixture.db.with_name("config.json")
        config = json.loads(config_path.read_bytes())
        config["reservation_ttl_min"] = lease_seconds / 60
        encoded = json.dumps(config, sort_keys=True).encode()
        config_path.write_bytes(encoded)
        self.fixture.fixture.generation["config_digest"] = hashlib.sha256(encoded).hexdigest()
        demand, command = self.fixture.admitted()
        with patch.object(launch_module.ScopeLaunch, "create_inert", autospec=True,
                side_effect=self.fixture.create_wrapper):
            owner = scope.ExperimentNativeScope.prepare(demand, command)
        self.fixture.scopes.append(owner)
        self.owner = owner
        self.original_rows = self.fixture.rows("reservations")
        self.assertEqual(self.original_rows[0]["expires_at"], NOW + lease_seconds)
        self.assertTrue(owner._registered)
        return owner

    def change_expiry(self, expiry):
        with self.owner._scope(daily=True):
            with self.owner.daily_store._transaction() as conn:
                conn.execute("UPDATE reservations SET expires_at=?,writer_protocol=1,"
                    "writer_revision=writer_revision+1 WHERE execution_id=?",
                    (expiry, self.owner.demand._snapshot.execution_id))

    def authorize(self, owner, *, monotonic_ns=None):
        if monotonic_ns is None:
            monotonic_ns = int((owner.deadline - 100) * 1_000_000_000)
        with patch.object(scope.time, "monotonic_ns", return_value=monotonic_ns):
            return owner._authorize_launch(owner.launch, owner.job)

    def test_original_allocation_bounds_are_frozen_inside_validated_transaction(self):
        owner = self.prepared()
        events, observed = [], []
        transaction = owner.daily_store._transaction
        coverage, validated = owner._coverage_locked, []
        monotonic_ns = int((owner.deadline - 100) * 1_000_000_000)
        def observe_coverage(conn, **kwargs):
            result = coverage(conn, **kwargs)
            self.assertTrue(conn.in_transaction)
            validated.append(conn)
            return result
        @contextmanager
        def observe_transaction():
            with transaction() as conn:
                yield conn
                if any(conn is original for original in validated):
                    self.assertTrue(conn.in_transaction)
                    observed.append(dict(owner._launch_bounds))
        def monotonic_sample():
            events.append("monotonic")
            return monotonic_ns
        def wall_sample():
            if events:
                events.append("wall")
            return NOW
        with patch.object(owner.daily_store, "_transaction", side_effect=observe_transaction), \
                patch.object(owner, "_coverage_locked", side_effect=observe_coverage), \
                patch.object(scope.time, "monotonic_ns", side_effect=monotonic_sample), \
                patch.object(scope.time, "time", side_effect=wall_sample):
            bounds = owner._authorize_launch(owner.launch, owner.job)
        expected = dict(reservation_id=owner.reservation_id, binding_sha256=owner._daily_binding_sha256,
            expires_at=NOW + 40, lease_deadline_monotonic_ns=monotonic_ns + 40_000_000_000)
        self.assertEqual(bounds, expected)
        self.assertEqual(len(validated), 1)
        self.assertEqual(observed, [expected])
        self.assertEqual(events[:2], ["monotonic", "wall"])
        self.assertIs(type(bounds), dict)
        self.assertIsNot(bounds, owner._launch_bounds)
        bounds["expires_at"] += 1000
        self.assertEqual(owner._launch_bounds, expected)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_admitted_experiment_expiry_mutation_is_rejected_and_original_bound_remains(self):
        owner = self.prepared(lease_seconds=40)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "experiment_demand_immutable"):
            self.change_expiry(NOW + 90)
        monotonic_ns = int((owner.deadline - 100) * 1_000_000_000)
        bounds = self.authorize(owner, monotonic_ns=monotonic_ns)
        self.assertEqual(bounds["expires_at"], NOW + 40)
        self.assertEqual(bounds["lease_deadline_monotonic_ns"], monotonic_ns + 40_000_000_000)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_earlier_retained_restriction_is_not_overwritten_by_original_allocation(self):
        owner = self.prepared(lease_seconds=90)
        # Explicit strengthen-only restriction fixture. No allocation mutation
        # or heartbeat authority is fabricated; actual coverage still reads 90.
        owner._restriction_lease_deadline = NOW + 25
        monotonic_ns = int((owner.deadline - 100) * 1_000_000_000)
        bounds = self.authorize(owner, monotonic_ns=monotonic_ns)
        self.assertEqual(bounds["expires_at"], NOW + 25)
        self.assertEqual(bounds["lease_deadline_monotonic_ns"], monotonic_ns + 25_000_000_000)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_original_scope_deadline_caps_long_allocation(self):
        owner = self.prepared(lease_seconds=300)
        bounds = self.authorize(owner)
        self.assertEqual(bounds["lease_deadline_monotonic_ns"], int(owner.deadline * 1_000_000_000))

    def test_expired_earlier_restriction_refuses_live_original_allocation_without_retry(self):
        owner = self.prepared(lease_seconds=90)
        # Fault fixture tightens only the already captured local restriction.
        # The real immutable allocation remains valid through NOW + 90.
        owner._restriction_lease_deadline = NOW + 40
        with patch.object(scope.time, "time", return_value=NOW + 41), \
                self.assertRaisesRegex(scope.ExperimentScopeError, "launch_lease_expired"):
            self.authorize(owner)
        self.assertIsNone(owner._launch_bounds)
        self.assertTrue(owner._launch_authorization_attempted)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "launch_binding_changed"):
            self.authorize(owner)
        self.assertEqual(owner.restore().flags, 0)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)
        self.assertEqual(self.fixture.exchange_operations, [])

    def test_journal_failure_retains_same_bounds_and_refuses_new_authorization(self):
        owner = self.prepared()
        original = owner.journal.begin_launch_locked
        def fail_after_intent(conn):
            original(conn)
            raise RuntimeError("synthetic post-intent journal failure")
        with patch.object(owner.journal, "begin_launch_locked", side_effect=fail_after_intent), \
                self.assertRaisesRegex(RuntimeError, "post-intent journal failure"):
            self.authorize(owner)
        bounds = dict(owner._launch_bounds)
        with patch.object(scope.time, "time", return_value=NOW - 1000), \
                patch.object(owner, "_coverage_locked", side_effect=AssertionError("retried allocation validation")), \
                self.assertRaisesRegex(scope.ExperimentScopeError, "launch_binding_changed"):
            self.authorize(owner)
        self.assertEqual(owner._launch_bounds, bounds)
        self.assertEqual(owner.restore().flags, 0)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_positive_allocation_sql_exit_ack_loss_keeps_original_bounds(self):
        owner = self.prepared()
        transaction = owner.daily_store._transaction
        coverage, validated, lost = owner._coverage_locked, [], []
        def observe_coverage(conn, **kwargs):
            result = coverage(conn, **kwargs)
            self.assertTrue(conn.in_transaction)
            validated.append(conn)
            return result
        @contextmanager
        def lose_exit_ack():
            with transaction() as conn:
                yield conn
            if any(conn is original for original in validated):
                # The exact allocation reader's real transaction and connection
                # positively completed. Earlier POLICY nonce writes are intact.
                lost.append(conn)
                raise RuntimeError("synthetic allocation SQL exit acknowledgement lost")
        with patch.object(owner.daily_store, "_transaction", side_effect=lose_exit_ack), \
                patch.object(owner, "_coverage_locked", side_effect=observe_coverage), \
                self.assertRaisesRegex(RuntimeError, "exit acknowledgement lost"):
            self.authorize(owner)
        self.assertEqual(len(validated), 1)
        self.assertEqual(len(lost), 1)
        self.assertIs(lost[0], validated[0])
        bounds = dict(owner._launch_bounds)
        with patch.object(owner, "_coverage_locked", side_effect=AssertionError("retried allocation")), \
                self.assertRaisesRegex(scope.ExperimentScopeError, "launch_binding_changed"):
            self.authorize(owner)
        self.assertEqual(owner._launch_bounds, bounds)
        self.assertFalse(owner._launch_authorized)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_sealed_original_launcher_cannot_capture_bounds_or_enter_sql(self):
        owner = self.prepared()
        owner.launch.seal()
        with patch.object(owner.daily_store, "_transaction", side_effect=AssertionError("sealed launch read SQL")), \
                self.assertRaisesRegex(scope.ExperimentScopeError, "launch_binding_changed"):
            self.authorize(owner)
        self.assertIsNone(owner._launch_bounds)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)

    def test_successful_original_authorization_cannot_replay_with_new_clock(self):
        owner = self.prepared()
        original = self.authorize(owner)
        with patch.object(scope.time, "time", return_value=NOW - 1000), \
                patch.object(owner, "_coverage_locked", side_effect=AssertionError("authorization replay")), \
                self.assertRaisesRegex(scope.ExperimentScopeError, "launch_binding_changed"):
            self.authorize(owner)
        self.assertEqual(owner._launch_bounds, original)
        self.assertEqual(self.fixture.rows("reservations"), self.original_rows)
