"""Guardian host consumes real two-ledger authority with explicit native fixtures.

The existing SQLite stores, registration, launch owner, control consumer and
typed host authority are real. Process/pipe/native readiness and the parent
role Release witness are explicit fixtures; no workload or Job starts,
and these tests are not Windows capability or complete cohort evidence.
"""
from dataclasses import replace
import copy
import hashlib
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import guardian_host as module
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.experiment_host_authority import ExperimentBackedHostAuthority, ExperimentHostAuthorityError
from sentinel.adaptive.experiment_host_roles import GuardianRoleSpec
from sentinel.adaptive.experiment_host_transport import ExperimentChildBinding
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.guardian_control import GuardianControl
from sentinel.adaptive.guardian_host import GuardianHost, GuardianHostRefused
from sentinel.adaptive.guardian_registration import GuardianRegistration
from sentinel.adaptive.policy import PolicyBusy
from sentinel.adaptive.store import LifecycleStore
from sentinel.adaptive.telemetry import ResidentTelemetry, _UnavailableTelemetry
from tests import test_adaptive_experiment_host_authority as fixtures
from tests import test_adaptive_guardian_host as host_fixtures
from tests.test_adaptive_host_authority import SYNTHETIC


class TelemetryThreadFixture:
    """No actual thread: only the original retained completion boundary."""
    def __init__(self, sink):
        self.sink = sink

    def join(self, timeout):
        return None

    def is_alive(self):
        return not self.sink._done


class GuardianExperimentHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentHostAuthorityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        # The parent fixture owns admission. A resident guardian opens that
        # existing ledger; the coordinator's creation-capable store is not a
        # valid GuardianLifecycle registry and must never weaken that check.
        self.fixture.store = LifecycleStore(self.fixture.store.db_path, existing_path=True,
            local_host_id=self.fixture.store.local_host_id, policy_provider=self.fixture.fixture.policy)
        self.authority, self.binding = self.fixture.guardian()
        self.store, self.daily = self.fixture.store, self.fixture.host.store
        self.guardian = self.fixture.guardian_process
        directory = Path(self.store.db_path).parent
        self.journal_dir = directory / "guardian-journal"
        self.journal_dir.mkdir()
        self.profile = directory / "guardian-profile.json"
        raw = module.DEFAULT_PROFILE.read_bytes()
        self.profile.write_bytes(raw)
        self.spec = GuardianRoleSpec(self.binding.manifest.actor_member_id, str(directory),
            str(self.journal_dir), str(self.profile), hashlib.sha256(raw).hexdigest(),
            "fixture-experiment-guardian", *(str(uuid4()) for _ in range(5)),
            self.binding.manifest.isolated_policy_instance_id)
        self.release_calls = []
        self.release_error = None
        self.release_context = {}
        self.listeners = []
        self.events = []
        self.registry = host_fixtures.install_pipe_fixture(self)

        def released(binding, spec):
            self.assertIs(binding, self.binding)
            self.assertIs(spec, self.spec)
            self.release_calls.append(spec)
            if self.release_error is not None:
                raise self.release_error

        def listener(endpoint):
            self.assertFalse(self.fixture.fixture.policy.active)
            self.assertFalse(self.fixture.host.fixture.fixture.policy.active)
            self.assertEqual(self.fixture.fixture.daily_transactions, [])
            value = host_fixtures.Listener(endpoint.name, self.events)
            self.listeners.append(value)
            return value

        def released_context(binding, spec):
            released(binding, spec)
            return dict(self.release_context)

        for override in (
            # This exact-class synthetic Release witness marks only this
            # private role; the actual parent/child protocol has separate tests.
            patch.object(ExperimentChildBinding, "require_role_release", released, create=True),
            patch.object(ExperimentChildBinding, "role_release_context", released_context),
            patch.object(module, "read_host_capability", return_value=SYNTHETIC),
            patch("sentinel.adaptive.pipe_windows.NativePipeListener", side_effect=listener),
            patch.object(GuardianHost, "_start_telemetry"),
        ):
            override.start()
            self.addCleanup(override.stop)

    def build(self, **overrides):
        arguments = dict(child_binding=self.binding, isolated_store=self.store, daily_store=self.daily)
        arguments.update(overrides)
        return GuardianHost.for_experiment(self.spec, **arguments)

    def floor(self):
        original = self.fixture.host
        return original.fixture.assert_retained(original.owner)

    def test_start_connects_actual_owner_and_control_to_original_typed_authority(self):
        before = self.floor()
        with patch.object(module, "HostAuthority", side_effect=AssertionError("ordinary authority fallback")), \
                patch("sentinel.adaptive.identity.VerifiedProcess.current",
                      side_effect=AssertionError("replacement guardian handle")):
            host = self.build()
            self.assertIs(self.build(), host)
            host.start()
        self.assertIs(type(host.authority), ExperimentBackedHostAuthority)
        self.assertIs(host.authority, self.authority)
        self.assertIs(host.guardian, self.binding._process)
        self.assertIs(type(host.owner), GuardianLaunchOwner)
        self.assertIs(type(host.control), GuardianControl)
        self.assertIs(host.owner.authority, self.authority)
        self.assertIs(host.control.owner, host.owner)
        self.assertTrue(host.registered)
        with sqlite3.connect(self.store.db_path) as conn:
            row = conn.execute("SELECT guardian_epoch,mode,policy_entry_nonce FROM adaptive_runtime").fetchone()
            actors = conn.execute("SELECT role,pid,created_filetime_100ns FROM adaptive_infrastructure").fetchall()
        self.assertEqual(row, (self.spec.guardian_epoch, "off", None))
        self.assertEqual(actors, [("guardian", self.guardian.identity.pid,
                                   str(self.guardian.identity.created_filetime_100ns))])
        self.assertEqual(self.floor(), before)
        self.assertEqual(len(self.listeners), 4)

    def test_registration_holds_daily_before_isolated_and_closes_sql_before_publication(self):
        host = self.build()
        publish = GuardianRegistration._publish
        observations = []

        def observed(registration):
            self.assertIs(registration, host._registration)
            self.assertTrue(self.fixture.host.fixture.fixture.policy.active)
            self.assertTrue(self.fixture.fixture.policy.active)
            self.assertEqual(self.fixture.fixture.daily_transactions, [])
            self.assertEqual(self.authority._reads, [])
            self.assertIsNotNone(self.authority._actor_active)
            self.authority.assert_actor_registration_ready(registration)
            observations.append(registration)
            return publish(registration)

        with patch.object(GuardianRegistration, "_publish", observed):
            host.start()
        self.assertEqual(observations, [host._registration])
        self.assertIsNone(self.authority._actor_active)
        self.assertIsNone(self.authority._guard)
        self.assertFalse(self.fixture.host.fixture.fixture.policy.active)
        self.assertFalse(self.fixture.fixture.policy.active)

    def test_registration_clear_ack_loss_reconciles_original_after_parent_loss(self):
        host = self.build()
        clear = self.store._policy._clear
        failed = False

        def lost_ack(guard):
            nonlocal failed
            clear(guard)
            if host._registration is not None and host._registration.after is not None and not failed:
                failed = True
                raise sqlite3.OperationalError("fixture lost registration clear ACK")

        with patch.object(self.store._policy, "_clear", lost_ack):
            with self.assertRaisesRegex(GuardianHostRefused, "registry_unavailable"):
                host.start()
        registration = host._registration
        self.assertTrue(registration.pending)
        self.assertIsNotNone(registration._publication_pins)
        self.assertEqual(self.listeners, [])
        before = self.floor()
        self.release_error = RuntimeError("fixture parent unavailable")
        release_count = len(self.release_calls)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("replacement guard")), \
                patch.object(registration, "_publish", side_effect=AssertionError("duplicate publication")):
            host._register()
        self.assertIs(host._registration, registration)
        self.assertTrue(registration.result.complete)
        self.assertEqual(len(self.release_calls), release_count)
        self.assertEqual(self.floor(), before)
        with self.assertRaisesRegex(RuntimeError, "parent unavailable"):
            host.start()
        self.assertEqual(self.listeners, [])

    def test_busy_without_postimage_must_reacquire_fresh_actor_scope(self):
        host = self.build()
        with patch.object(self.store._policy, "prepare", side_effect=PolicyBusy("fixture isolated busy")):
            with self.assertRaisesRegex(GuardianHostRefused, "registry_unavailable"):
                host.start()
        registration = host._registration
        self.assertTrue(registration.pending)
        self.assertIsNone(registration._publication_pins)
        self.release_error = RuntimeError("fixture role release unavailable")
        with patch.object(registration, "tick", side_effect=AssertionError("unfenced registration")):
            with self.assertRaisesRegex(GuardianHostRefused, "registry_unavailable") as rejected:
                host._register()
        self.assertEqual(rejected.exception.detail, "RuntimeError")
        self.assertIs(host._registration, registration)
        self.assertFalse(host.registered)
        self.assertEqual(self.listeners, [])
        self.release_error = None
        host.start()
        self.assertIs(host._registration, registration)
        self.assertTrue(host.registered)

    def test_missing_parent_release_refuses_without_registering_or_replacement(self):
        failure = RuntimeError("fixture_role_not_released")
        self.release_error = failure
        with self.assertRaises(RuntimeError) as raised:
            self.build()
        self.assertIs(raised.exception, failure)
        host = failure.experiment_guardian_host
        self.assertIs(host, self.binding._experiment_guardian_host)
        self.assertIs(host._experiment_original[4], self.guardian)
        self.assertIs(self.binding._process, self.guardian)
        self.assertIsNone(getattr(host, "owner", None))
        self.assertIsNone(getattr(host, "_registration", None))
        self.release_error = None
        with self.assertRaisesRegex(GuardianHostRefused, "construction_unsettled"):
            self.build()
        self.assertEqual(self.listeners, [])

    def test_equal_role_copy_cannot_replace_original_factory_inputs(self):
        host = self.build()
        with self.assertRaisesRegex(GuardianHostRefused, "original_host_changed"):
            GuardianHost.for_experiment(replace(self.spec), child_binding=self.binding,
                isolated_store=self.store, daily_store=self.daily)
        self.assertIs(self.build(), host)

    def test_supervisor_parent_context_is_consumed_and_cannot_change_before_start(self):
        parent = self.binding.manifest.endpoint.server_identity
        instance_id = str(uuid4())
        self.release_context = dict(parent_identity=parent, parent_instance_id=instance_id)
        host = self.build()
        self.assertIs(host.parent_identity, parent)
        self.assertEqual(host.parent_instance_id, instance_id)
        host.parent_instance_id = str(uuid4())
        with self.assertRaisesRegex(GuardianHostRefused, "original_host_changed"):
            host.start()
        host.parent_instance_id = instance_id
        self.release_context["parent_instance_id"] = str(uuid4())
        with self.assertRaisesRegex(GuardianHostRefused, "parent_release_changed"):
            host.start()
        self.assertIsNone(host.owner)
        self.assertEqual(self.listeners, [])

    def test_profile_change_after_factory_refuses_before_registration(self):
        host = self.build()
        self.profile.write_bytes(self.profile.read_bytes() + b" ")
        with self.assertRaisesRegex(GuardianHostRefused, "profile_changed") as raised:
            host.start()
        self.assertIs(raised.exception.experiment_guardian_host, host)
        self.assertIs(raised.exception.experiment_child_binding, self.binding)
        self.assertIsNone(host._registration)
        self.assertIsNone(host.owner)
        self.assertEqual(self.listeners, [])

    def test_original_authority_cleanup_hold_refuses_start(self):
        host = self.build()
        self.authority._body_attempt = {"returned": False, "error": RuntimeError("fixture_unknown_cleanup")}
        with self.assertRaisesRegex(ExperimentHostAuthorityError, "cleanup_unverified"):
            host.start()
        self.assertIsNone(host._registration)
        self.assertEqual(self.listeners, [])

    def test_missing_job_publication_denies_actual_host_authority_without_releasing_capacity(self):
        host = self.build()
        host.start()
        self.fixture.admit()
        before = self.floor()
        with self.assertRaisesRegex(ExperimentHostAuthorityError, "daily_job_required"):
            with host.owner.authority.new_work_scope(self.fixture.execution_id, operation="claim"):
                self.fail("unpublished Job obtained a claim scope")
        self.assertEqual(self.floor(), before)
        self.assertEqual(len(self.fixture.fixture.rows("reservations")), 1)
        self.assertEqual(host.owner.retained_execution_ids, ())
        self.assertEqual(host.control.backend_calls, [])

    def test_dead_parent_does_not_block_drain_or_close_borrowed_bootstrap_handles(self):
        host = self.build()
        host.start()
        original_handle = self.guardian._handle
        self.binding._peer._backend.status = IdentityStatus.DEAD
        host.begin_drain()
        self.assertTrue(host.owner._draining)
        self.assertTrue(host.control._draining)
        result = host.close()
        self.assertEqual(result["event"], "guardian_host_closed")
        self.assertEqual(self.guardian._handle, original_handle)
        self.assertTrue(self.binding.custody_pending)
        self.assertTrue(all(listener.closed for listener in self.listeners))
        closed = host.closed_experiment_custody()
        self.assertEqual(closed, ())
        self.assertIs(host.closed_experiment_custody(), closed)
        with self.assertRaisesRegex(GuardianHostRefused, "host_closed"):
            host.start()

    def telemetry(self, host):
        # Real sink/store, no thread start or file I/O. Explicitly model the
        # worker completion boundary rather than accepting a stopped dict.
        sink = ResidentTelemetry(data_dir=host.data_dir, role="guardian", identity=self.guardian.identity,
            instance_id=host.instance_id, excluded_paths=(host.journal_dir,))
        sink._thread = TelemetryThreadFixture(sink)
        host.telemetry = sink
        return sink

    def test_telemetry_pending_keeps_original_and_retries_without_fresh_parent(self):
        host = self.build()
        host.start()
        sink = self.telemetry(host)
        host.begin_drain()
        before = self.guardian._handle
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_cleanup_pending"):
            host.close()
        self.assertIs(host.telemetry, sink)
        self.assertFalse(host._experiment_closed)
        self.assertEqual(self.guardian._handle, before)
        self.assertTrue(self.binding.custody_pending)
        self.assertTrue(all(listener.closed for listener in self.listeners))
        with self.assertRaisesRegex(GuardianHostRefused, "host_not_closed"):
            host.closed_experiment_custody()
        with self.assertRaisesRegex(GuardianHostRefused, "host_closing"):
            host.start()
        closes = [event for event in self.events if event[0] == "close"]
        self.binding._peer._backend.status = IdentityStatus.DEAD
        sink._done = True
        result = host.close()
        self.assertTrue(result["telemetry"]["stopped"])
        self.assertGreater(result["telemetry"]["pending_records"], 0)
        self.assertEqual(host.closed_experiment_custody(), ())
        self.assertEqual([event for event in self.events if event[0] == "close"], closes)
        self.assertIs(host.telemetry, sink)
        self.assertEqual(self.guardian._handle, before)

    def test_telemetry_owner_replacement_cannot_turn_pending_into_closed(self):
        host = self.build()
        host.start()
        original = self.telemetry(host)
        host.begin_drain()
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_cleanup_pending"):
            host.close()
        replacement = self.telemetry(host)
        replacement._stop = replacement._done = True
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_owner_changed"):
            host.close()
        host.telemetry = original
        original._done = True
        host.close()
        self.assertEqual(host.closed_experiment_custody(), ())

    def test_default_telemetry_constructor_failure_has_known_empty_native_custody(self):
        host = self.build()
        host.start()
        error = RuntimeError("fixture constructor failure before assignment")
        host.telemetry = _UnavailableTelemetry(error)
        host._telemetry_start_error = error
        host.begin_drain()
        host.close()
        self.assertEqual(host.closed_experiment_custody(), ())
        host._telemetry_start_error = RuntimeError("replacement diagnostic")
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_cleanup_pending"):
            host.closed_experiment_custody()

    def test_original_sink_before_thread_creation_can_close_without_claiming_worker_completion(self):
        host = self.build()
        host.start()
        sink = ResidentTelemetry(data_dir=host.data_dir, role="guardian", identity=self.guardian.identity,
            instance_id=host.instance_id, excluded_paths=(host.journal_dir,))
        host.telemetry = sink
        self.assertIsNone(sink._thread)
        host.begin_drain()
        result = host.close()
        self.assertFalse(result["telemetry"]["stopped"])
        self.assertEqual(host.closed_experiment_custody(), ())

    def test_closed_telemetry_retained_file_or_native_quarantine_refuses_receipt(self):
        host = self.build()
        host.start()
        sink = self.telemetry(host)
        sink._done = True
        host.begin_drain()
        host.close()
        retained = object()  # explicit unknown owner fixture, never a file
        sink.store._owners.append(retained)
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_cleanup_pending"):
            host.closed_experiment_custody()
        sink.store._owners.remove(retained)
        sink.store._quarantined = True
        with self.assertRaisesRegex(GuardianHostRefused, "telemetry_cleanup_pending"):
            host.closed_experiment_custody()

    def test_equal_owner_copy_cannot_replace_original_custody_before_close(self):
        host = self.build()
        host.start()
        original = host.owner
        host.begin_drain()
        host.owner = copy.copy(original)
        with self.assertRaisesRegex(GuardianHostRefused, "original_owner_changed"):
            host.close()
        self.assertFalse(any(listener.closed for listener in self.listeners))
        host.owner = original
        host.close()
        self.assertEqual(host.closed_experiment_custody(), ())

    def test_constructor_exception_keeps_original_partial_host(self):
        failure = RuntimeError("fixture_constructor_failure")
        with patch.object(GuardianHost, "__init__", side_effect=failure):
            with self.assertRaises(RuntimeError) as raised:
                self.build()
        self.assertIs(raised.exception, failure)
        owner = failure.experiment_guardian_host
        self.assertIs(owner, self.binding._experiment_guardian_host)
        with self.assertRaisesRegex(GuardianHostRefused, "construction_unsettled"):
            self.build()
        self.assertFalse(self.binding._closed)


if __name__ == "__main__":
    unittest.main()
