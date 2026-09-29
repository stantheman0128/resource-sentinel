"""Guardian host consumes real two-ledger authority with explicit native fixtures.

The existing SQLite stores, registration, launch owner, control consumer and
typed host authority are real. Process/pipe/native readiness and the pending
parent role Release contract are explicit fixtures; no workload or Job starts,
and these tests are not Windows capability or complete cohort evidence.
"""
from dataclasses import replace
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
from tests import test_adaptive_experiment_host_authority as fixtures
from tests import test_adaptive_guardian_host as host_fixtures
from tests.test_adaptive_host_authority import SYNTHETIC


class GuardianExperimentHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentHostAuthorityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
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
            value = host_fixtures.Listener(endpoint.name, self.events)
            self.listeners.append(value)
            return value

        for override in (
            # Until the root's fixed bootstrap/Release protocol is connected,
            # this exact-class fixture marks only this private role as released.
            patch.object(ExperimentChildBinding, "require_role_release", released, create=True),
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

    def test_missing_parent_release_refuses_without_registering_or_replacement(self):
        failure = RuntimeError("fixture_role_not_released")
        self.release_error = failure
        with self.assertRaises(RuntimeError) as raised:
            self.build()
        self.assertIs(raised.exception, failure)
        host = failure.experiment_guardian_host
        self.assertIs(host, self.binding._experiment_guardian_host)
        self.assertIs(host.guardian, self.guardian)
        self.assertIsNone(host.owner)
        self.assertIsNone(host._registration)
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
        original_handle = self.guardian.handle
        self.binding._peer._backend.status = IdentityStatus.DEAD
        host.begin_drain()
        self.assertTrue(host.owner._draining)
        self.assertTrue(host.control._draining)
        result = host.close()
        self.assertEqual(result["event"], "guardian_host_closed")
        self.assertEqual(self.guardian.handle, original_handle)
        self.assertTrue(self.binding.custody_pending)
        self.assertTrue(all(listener.closed for listener in self.listeners))
        with self.assertRaisesRegex(GuardianHostRefused, "host_closed"):
            host.start()

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
