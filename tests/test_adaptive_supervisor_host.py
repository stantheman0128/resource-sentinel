"""Supervisor process host: epoch minting, witness custody and replacement.

Process creation is an explicit in-process backend. It hands out fixed handle
numbers and records what it was asked to create; it starts no process, so no
claim here is evidence of Windows behaviour. GuardianSupervisor is replaced by
a fixture that reports one status at a time, because its own rules have a
dedicated test module.

The capability preflight is live, and the subprocess smoke expects this
machine's real refusal.
"""
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import legacy_writer as writer
from sentinel.adaptive import supervisor_host as module
from sentinel.adaptive import supervisor_reconcile as reconciliation
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.host_authority import HostCapabilityUnsupported
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_host import (
    EXIT_REFUSED, EXIT_UNSETTLED, SupervisorHost, SupervisorHostRefused, mint_guardian_epoch,
    quote_argument,
)
from tests import test_adaptive_lifecycle as lifecycle_fixtures
from tests.test_adaptive_host_authority import SYNTHETIC, live_capability_refusal
from tests.test_adaptive_legacy_writer import SyntheticIdentityBackend


REPO_ROOT = Path(module.__file__).resolve().parents[2]
LOGON = "S-1-5-5-1-2"
WRAPPER = lifecycle_fixtures.WRAPPER


class Startup:
    """Explicit singleton/freshness fixture; never inspects host runtime state."""
    def __init__(self):
        self.binding = PolicyBinding("11111111-1111-4111-8111-111111111111", LOGON)
        self.acquired = self.closed = False
        self.acquire_error = self.fresh_error = None
        self.fresh_checks = 0
        self.policy_pending = self.policy_quarantined = False
        self.policy_guard = self.policy_result = None

    def acquire(self):
        if self.acquire_error is not None:
            raise self.acquire_error
        self.acquired = True

    def assert_held(self):
        if not self.acquired or self.closed:
            raise LifecycleError("fixture_startup_not_held")

    def assert_fresh(self):
        self.assert_held()
        self.fresh_checks += 1
        if self.fresh_error is not None:
            raise self.fresh_error
        self.policy_pending = False

    def close(self):
        self.closed = True


class Janitor:
    def __init__(self):
        self.ticks = 0
        self.result = reconciliation.ReconcileResult(True, False, False, None)

    def tick(self):
        self.ticks += 1
        return self.result


class CreationWitness:
    """Trusted in-process creation seam, distinct from PID reopening."""
    def __init__(self, process, epoch):
        self.process, self.guardian_epoch = process, epoch

    def close(self):
        self.process.close()


def rollover_fixture(previous):
    """Host-order tests inject settled rollover; production has separate tests."""
    epoch = mint_guardian_epoch()
    if epoch == previous.epoch:
        raise SupervisorHostRefused("supervisor_host_epoch_reused")
    return epoch


def supervision(status, **overrides):
    values = dict(guardian_status=status, inventory_verified=True, known_executions=(),
                  restored_executions=(), unresolved_executions=(), slot_released_executions=(),
                  finalized_executions=(), drain_unresolved_executions=(), inventory_error=None)
    values.update(overrides)
    return SimpleNamespace(**values)


class Creation:
    """Records creations and hands out handle numbers. It starts nothing."""

    def __init__(self):
        self.created = []
        self.closed = []
        self.next_handle = 900
        self.next_pid = 4000
        self.create_error = None
        # Which creation the error starts at, counting from zero. The default
        # fails every creation; a later index fails only the children after it.
        self.create_from = 0
        self.close_error = None

    def create(self, executable, arguments, cwd):
        if self.create_error is not None and len(self.created) >= self.create_from:
            raise self.create_error
        self.next_handle += 2
        self.next_pid += 1
        self.created.append({"executable": executable, "arguments": list(arguments), "cwd": str(cwd)})
        return SimpleNamespace(hProcess=self.next_handle, hThread=self.next_handle + 1,
                               dwProcessId=self.next_pid, dwThreadId=self.next_pid + 1)

    def close_handle(self, handle):
        self.closed.append(handle)
        if self.close_error is not None:
            raise self.close_error


class Supervisor:
    def __init__(self, guardian, epoch):
        self.guardian, self.epoch = guardian, epoch
        self.status = IdentityStatus.ALIVE
        self.ticks = 0
        self.closed = False
        self.close_error = None
        self.close_calls = 0

    def tick(self, *, now=None):
        if self.closed:
            raise AssertionError("closed supervisor ticked")
        self.ticks += 1
        return supervision(self.status)

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class SupervisorHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.creation = Creation()
        self.supervisors = []
        self.attach_error = None
        self.witness_error = None
        self.witnessed = []
        # Which witness the error starts at, counting from one, so a test can
        # give the guardian a witness and deny the helper one.
        self.witness_from = 1
        self.removals = []
        self.removal_result = (True, None)
        self.helper_removals = []
        self.helper_removal_result = (True, None)
        self.helper_profile = self.directory / "helper-profile.json"
        self.startup = Startup()
        self.janitor = Janitor()

    def build(self, **overrides):
        arguments = dict(data_dir=self.directory, journal_dir=self.directory,
                         max_guardians=2, sleep=lambda seconds: None)
        arguments.update(overrides)
        host = SupervisorHost(**arguments)
        host.capability = SYNTHETIC
        host.store = SimpleNamespace(name="fixture-store")
        host.journal = SimpleNamespace(name="fixture-journal")
        host.creation = self.creation
        host.capability_logon = lambda: LOGON
        host._attach = self.attach
        host._attach_created = self.attach
        host._capture_guardian_creation = self.capture_creation
        host._rollover_epoch = rollover_fixture
        # Dedicated registry integration below checks the production POLICY
        # span; these host-order tests have no real ledger in this fixture.
        host._start_initial_guardian = lambda: host._start_guardian()
        self.startup.acquire()
        host.startup, host.janitor = self.startup, self.janitor
        # The registry removal itself runs against a real ledger in
        # SupervisorHostRegistryTests below.
        host._unregister = self.unregister
        return host

    def unregister(self, role, child):
        # How many children exist at this point records the ordering: the row
        # is released before any replacement is created. A helper has no epoch,
        # so its pid is what identifies the removal.
        if role == "helper":
            self.helper_removals.append((child.pid, len(self.creation.created)))
            return self.helper_removal_result
        self.removals.append((child.epoch, len(self.creation.created)))
        return self.removal_result

    def attach(self, guardian):
        if self.attach_error is not None:
            raise SupervisorHostRefused("supervisor_host_attach_unavailable", self.attach_error)
        supervisor = Supervisor(guardian, guardian.epoch)
        self.supervisors.append(supervisor)
        return supervisor

    def witness(self, handle, *, expected_pid, expected_logon_id):
        self.witnessed.append(expected_pid)
        if self.witness_error is not None and len(self.witnessed) >= self.witness_from:
            raise self.witness_error
        process = SimpleNamespace(handle=handle, pid=expected_pid, logon=expected_logon_id,
                                  closed=False)
        process.observe = lambda: SimpleNamespace(status=IdentityStatus.ALIVE)
        process.close = lambda: setattr(process, "closed", True)
        return process

    def capture_creation(self, handle, pid, epoch):
        return CreationWitness(self.witness(handle, expected_pid=pid,
                                           expected_logon_id=LOGON), epoch)

    def started(self, **overrides):
        host = self.build(**overrides)
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            host.guardian = host._start_guardian()
            host.supervisor = host._attach(host.guardian)
            if host.helper_profile_path is not None:
                host.helper = host._start_helper()
        return host

    def with_helper(self, **overrides):
        """A started host that also supervises one helper child."""
        overrides.setdefault("helper_profile_path", self.helper_profile)
        overrides.setdefault("max_helpers", 2)
        return self.started(**overrides)

    def start_through_main_path(self, **overrides):
        """Run the production start(), with the ledger and journal patched out."""
        host = self.build(**overrides)
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC), \
                patch("sentinel.adaptive.store.LifecycleStore", return_value=host.store), \
                patch("sentinel.adaptive.recovery_journal.RecoveryJournal",
                      return_value=host.journal), \
                patch("sentinel.adaptive.supervisor_startup.SupervisorStartup", return_value=self.startup), \
                patch.object(reconciliation, "FinishedBarrierJanitor", return_value=self.janitor), \
                patch.object(module, "_Creation", return_value=self.creation), \
                patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                      side_effect=self.witness):
            return host, host.start()

    def observing(self, host, status):
        """What the retained helper witness reports on the next iteration."""
        host.helper.process.observe = lambda: SimpleNamespace(status=status)

    def iterate(self, host):
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            return host.run_once()

    # --- epoch and creation ----------------------------------------------

    def test_every_minted_epoch_is_new(self):
        minted = {mint_guardian_epoch() for _ in range(64)}
        self.assertEqual(len(minted), 64)
        self.assertTrue(all(value.startswith("guardian-") for value in minted))

    def test_the_child_is_created_with_no_creation_flags_and_its_own_epoch(self):
        host = self.started()
        created = self.creation.created[0]
        self.assertEqual(created["arguments"][:2], ["-m", "sentinel.adaptive.guardian_host"])
        self.assertIn(host.guardian.epoch, created["arguments"])
        self.assertEqual(host.guardian.pid, 4001)
        # The thread handle is released; the process handle is retained.
        self.assertEqual(self.creation.closed, [903])
        self.assertEqual(host.guardian.creation_handle, 902)

    def test_the_witness_is_built_from_the_creation_handle(self):
        host = self.started()
        self.assertEqual(host.guardian.process.handle, host.guardian.creation_handle)
        self.assertEqual(host.guardian.process.pid, host.guardian.pid)

    def test_a_child_with_no_witness_is_retained_and_reported(self):
        self.witness_error = RuntimeError("fixture_duplicate_failed")
        host = self.build()
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            with self.assertRaises(SupervisorHostRefused) as caught:
                host._start_guardian()
        self.assertEqual(caught.exception.reason, "supervisor_host_guardian_unverified")
        self.assertEqual(host.unverified, [{"pid": 4001, "handle": 902,
                                            "epoch": host.unverified[0]["epoch"],
                                            "reason": "RuntimeError"}])
        # The creation handle is never closed here; it is the only witness.
        self.assertNotIn(902, self.creation.closed)

    def test_an_unwitnessed_child_blocks_a_clean_exit(self):
        host = self.build()
        host.unverified.append({"pid": 4001, "handle": 902, "epoch": "e", "reason": "fixture"})
        record = host.close()
        self.assertEqual(record["unverified"], host.unverified)

    # --- observation ------------------------------------------------------

    def test_an_alive_guardian_is_only_observed(self):
        host = self.started()
        record = host.run_once()
        self.assertEqual(record["guardian_status"], "alive")
        self.assertIsNone(record["replacement"])
        self.assertEqual(len(self.creation.created), 1)

    def test_unknown_never_restarts_anything(self):
        host = self.started()
        self.supervisors[0].status = IdentityStatus.UNKNOWN
        record = host.run_once()
        self.assertEqual(record["guardian_status"], "unknown")
        self.assertIsNone(record["replacement"])
        self.assertEqual(len(self.creation.created), 1)
        self.assertFalse(self.supervisors[0].closed)
        # No close, no replacement and no registry removal.
        self.assertEqual(self.removals, [])

    def test_an_unstarted_host_observes_nothing(self):
        with self.assertRaises(SupervisorHostRefused) as caught:
            self.build().run_once()
        self.assertEqual(caught.exception.reason, "supervisor_host_not_started")

    # --- replacement ------------------------------------------------------

    def replace(self, host):
        self.supervisors[-1].status = IdentityStatus.DEAD
        host.guardian.process.observe = lambda: SimpleNamespace(status=IdentityStatus.DEAD)
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            return host.run_once()

    def test_a_replacement_needs_a_successful_close_and_carries_a_new_epoch(self):
        host = self.started()
        first = host.guardian.epoch
        record = self.replace(host)
        self.assertTrue(self.supervisors[0].closed)
        self.assertEqual(record["replacement"]["started"], True)
        self.assertEqual(record["replacement"]["attached"], True)
        self.assertNotEqual(record["replacement"]["guardian_epoch"], first)
        self.assertEqual(record["replacement"]["previous_epoch"], first)
        self.assertEqual(len(self.creation.created), 2)

    def test_a_failed_close_starts_nothing(self):
        """Mirrors supervisor.close, which refuses while obligations remain."""
        host = self.started()
        self.supervisors[0].close_error = LifecycleError("supervisor_custody_unsettled")
        record = self.replace(host)
        self.assertEqual(record["replacement"], {"started": False,
                                                 "reason": "supervisor_custody_unsettled"})
        self.assertEqual(len(self.creation.created), 1)
        self.assertIsNotNone(host.supervisor)
        # Unsettled custody leaves the registry row alone.
        self.assertEqual(self.removals, [])

    def test_the_dead_guardian_row_is_released_before_a_replacement_is_started(self):
        host = self.started()
        previous = host.guardian.epoch
        record = self.replace(host)
        # One removal, for the dead guardian, while only its own child existed.
        self.assertEqual(self.removals, [(previous, 1)])
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]), (True, None))

    def test_a_replacement_that_cannot_attach_still_reports_the_removal(self):
        host = self.started()
        self.attach_error = "fixture_attach_unavailable"
        record = self.replace(host)
        self.assertEqual(record["replacement"],
                         {"started": True, "attached": False,
                          "reason": "supervisor_host_attach_unavailable",
                          "guardian_epoch": host.guardian.epoch,
                          "registry_removed": True,
                          "registry_reason": None})

    def test_a_reused_epoch_is_refused_before_a_child_exists(self):
        host = self.started()
        # Inject an invalid settled-rollover result at the explicit fixture
        # seam; production _start_guardian must reject it before Create.
        with patch.object(host, "_rollover_epoch", return_value=host.guardian.epoch):
            record = self.replace(host)
        self.assertEqual(record["replacement"], {"started": False,
                                                 "reason": "supervisor_host_epoch_reused",
                                                 "registry_removed": True,
                                                 "registry_reason": None})
        self.assertEqual(len(self.creation.created), 1)

    def test_the_guardian_budget_stops_further_replacements(self):
        host = self.started(max_guardians=1)
        previous = host.guardian.epoch
        record = self.replace(host)
        self.assertEqual(record["replacement"],
                         {"started": False, "reason": "supervisor_host_guardian_budget_exhausted",
                          "registry_removed": True, "registry_reason": None})
        self.assertEqual(len(self.creation.created), 1)
        # An exhausted budget does not keep the dead guardian in the registry.
        self.assertEqual(self.removals, [(previous, 1)])

    def test_guardian_registry_cleanup_retries_after_supervisor_close_with_budget_one(self):
        host = self.started(max_guardians=1)
        previous = host.guardian
        captured = host.supervisor
        self.removal_result = (False, "fixture_registry_pending")
        first = self.replace(host)
        self.assertEqual(first["replacement"]["reason"], "supervisor_host_guardian_row_retained")
        self.assertIs(host.guardian, previous)
        self.assertIsNone(host.supervisor)
        self.assertEqual(captured.close_calls, 1)
        self.assertFalse(host.run_once()["replacement"]["started"])
        self.removal_result = (True, None)
        settled = host.run_once()
        self.assertEqual(settled["replacement"]["reason"], "supervisor_host_guardian_budget_exhausted")
        self.assertTrue(settled["replacement"]["registry_removed"])
        self.assertEqual(captured.close_calls, 1)
        self.assertEqual(len(self.removals), 3)
        self.assertEqual(len(self.creation.created), 1)

    def test_rollover_pending_blocks_create_then_retries_same_settled_predecessor(self):
        host = self.started()
        previous = host.guardian
        with patch.object(host, "_rollover_epoch",
                          side_effect=SupervisorHostRefused("fixture_rollover_pending")) as rollover:
            first = self.replace(host)
            self.assertEqual(first["replacement"]["reason"], "fixture_rollover_pending")
            self.assertFalse(host.run_once()["replacement"]["started"])
            self.assertEqual(rollover.call_count, 2)
        self.assertIs(host.guardian, previous)
        self.assertEqual(len(self.creation.created), 1)
        self.assertTrue(self.iterate(host)["replacement"]["started"])
        self.assertEqual(len(self.creation.created), 2)

    def test_unknown_creation_outcome_never_attempts_a_second_create(self):
        host = self.build()
        self.creation.create_error = RuntimeError("fixture_create_outcome_unknown")
        with patch.object(self.creation, "create", wraps=self.creation.create) as create:
            with self.assertRaisesRegex(RuntimeError, "fixture_create_outcome_unknown"):
                host._start_guardian()
            self.creation.create_error = None
            with self.assertRaisesRegex(SupervisorHostRefused, "supervisor_host_creation_unsettled"):
                host._start_guardian()
            self.assertEqual(create.call_count, 1)
        self.assertTrue(host._creation_unknown)
        self.assertEqual(self.creation.created, [])

    def test_a_replacement_that_cannot_attach_is_never_ticked_through_a_closed_supervisor(self):
        host = self.started()
        self.attach_error = "fixture_attach_unavailable"
        record = self.replace(host)
        self.assertEqual(record["replacement"]["started"], True)
        self.assertEqual(record["replacement"]["attached"], False)
        self.assertIsNone(host.supervisor)
        self.assertTrue(self.supervisors[0].closed)
        # The next iteration reports the unattached guardian and retries.
        held = host.run_once()
        self.assertEqual((held["guardian_status"], held["attached"]), ("unattached", False))
        self.assertEqual(held["guardian_observed"], "alive")
        self.assertNotIn("guardian_running", held)
        self.attach_error = None
        retried = host.run_once()
        self.assertEqual(retried["attached"], True)
        self.assertEqual(host.supervisor.epoch, host.guardian.epoch)
        self.assertEqual(len(self.creation.created), 2)

    def test_an_unattached_guardian_is_reported_as_its_witness_observes_it(self):
        host = self.started()
        self.attach_error = "fixture_attach_unavailable"
        self.replace(host)
        host.guardian.process.observe = lambda: SimpleNamespace(status=IdentityStatus.DEAD)
        held = host.run_once()
        self.assertEqual((held["guardian_observed"], held["attached"]), ("dead", False))
        # Observation alone starts nothing and replaces nothing.
        self.assertIsNone(held["replacement"])
        self.assertEqual(len(self.creation.created), 2)

    def test_early_dead_child_uses_creation_capture_without_alive_only_attach(self):
        host = self.started()
        original = host.guardian
        host.supervisor = None
        original.process.observe = lambda: SimpleNamespace(status=IdentityStatus.DEAD)
        retained = Supervisor(original, original.epoch)
        retained.status = IdentityStatus.DEAD
        with patch.object(host, "_attach", side_effect=AssertionError("ALIVE-only attach used")) as alive, \
                patch.object(host, "_attach_created", return_value=retained) as created:
            result = host.run_once()
        alive.assert_not_called()
        created.assert_called_once_with(original)
        self.assertTrue(result["attached"])
        self.assertEqual(result["guardian_observed"], "dead")
        self.assertIs(host.supervisor, retained)
        self.assertIs(host.guardian, original)
        self.assertEqual(len(self.creation.created), 1)

    def test_created_capture_passes_original_creation_witness_to_production_attach(self):
        host = self.started()
        original = host.guardian
        host.supervisor = None
        del host._attach_created
        original.process.observe = lambda: SimpleNamespace(status=IdentityStatus.DEAD)
        retained = Supervisor(original, original.epoch)
        retained.status = IdentityStatus.DEAD
        with patch("sentinel.adaptive.supervisor.GuardianSupervisor.attach_created",
                   return_value=retained) as created:
            result = host.run_once()
        created.assert_called_once_with(host.store, host.journal,
            creation=original.creation_witness, guardian_epoch=original.epoch)
        self.assertTrue(result["attached"])
        self.assertIs(host.supervisor, retained)
        self.assertEqual(len(self.creation.created), 1)

    # --- the helper child --------------------------------------------------

    def helper_died(self, host):
        """The retained helper witness reports a verified death."""
        self.observing(host, IdentityStatus.DEAD)
        return self.iterate(host)

    def test_no_helper_is_created_or_reported_without_a_helper_profile(self):
        host, record = self.start_through_main_path()
        self.assertEqual(len(self.creation.created), 1)
        self.assertEqual(self.creation.created[0]["arguments"][:2],
                         ["-m", "sentinel.adaptive.guardian_host"])
        self.assertNotIn("helper", record)
        self.assertIsNone(host.helper)
        self.assertNotIn("helper", self.iterate(host))
        self.assertNotIn("helper_left_running", host.close())
        self.assertEqual(self.helper_removals, [])

    def test_the_helper_child_is_created_with_the_exact_arguments(self):
        host, record = self.start_through_main_path(helper_profile_path=self.helper_profile)
        self.assertEqual(len(self.creation.created), 2)
        self.assertEqual(self.creation.created[1]["arguments"],
                         ["-m", "sentinel.adaptive.helper_host",
                          "--data-dir", str(self.directory),
                          "--profile", str(self.helper_profile)])
        self.assertEqual(record["helper"], {"started": True, "pid": 4002})
        # The thread handle is released; the process handle is retained and is
        # the witness.
        self.assertEqual(self.creation.closed, [903, 905])
        self.assertEqual(host.helper.creation_handle, 904)
        self.assertEqual(host.helper.process.handle, 904)
        self.assertEqual(host.helper.process.logon, LOGON)

    def test_a_helper_with_no_witness_is_retained_and_reported(self):
        self.witness_error, self.witness_from = RuntimeError("fixture_duplicate_failed"), 2
        host, record = self.start_through_main_path(helper_profile_path=self.helper_profile)
        self.assertEqual(record["helper"], {"started": False, "detail": "RuntimeError",
                                            "reason": "supervisor_host_helper_unverified"})
        self.assertEqual(host.unverified, [{"pid": 4002, "handle": 904, "role": "helper",
                                            "reason": "RuntimeError"}])
        # The creation handle is never closed here; it is the only witness.
        self.assertNotIn(904, self.creation.closed)
        self.assertIsNone(host.helper)
        # Guardian supervision carries on.
        self.assertEqual(record["attached"], True)
        self.assertIsNotNone(host.supervisor)
        # An unwitnessed helper blocks a clean exit the same way.
        self.assertEqual(host.close()["unverified"], host.unverified)

    def test_a_helper_that_cannot_be_created_does_not_stop_the_guardian(self):
        self.creation.create_error = SupervisorHostRefused("supervisor_host_create_failed", 8)
        self.creation.create_from = 1
        host, record = self.start_through_main_path(helper_profile_path=self.helper_profile)
        self.assertEqual(record["helper"], {"started": False, "detail": 8,
                                            "reason": "supervisor_host_create_failed"})
        self.assertEqual(len(self.creation.created), 1)
        self.assertIsNone(host.helper)
        self.assertEqual((record["attached"], record["guardian_pid"]), (True, 4001))
        observed = self.iterate(host)
        self.assertEqual(observed["guardian_status"], "alive")
        self.assertEqual(observed["helper"], {"status": "absent", "started": False})
        self.assertEqual(len(self.creation.created), 1)

    def test_an_alive_helper_is_only_observed(self):
        host = self.with_helper()
        self.observing(host, IdentityStatus.ALIVE)
        record = self.iterate(host)
        self.assertEqual(record["helper"], {"status": "alive", "started": False})
        self.assertEqual(self.helper_removals, [])
        self.assertEqual(len(self.creation.created), 2)

    def test_an_unknown_helper_holds(self):
        host = self.with_helper()
        self.observing(host, IdentityStatus.UNKNOWN)
        record = self.iterate(host)
        self.assertEqual(record["helper"], {"status": "unknown", "started": False})
        self.assertEqual(self.helper_removals, [])
        self.assertEqual(len(self.creation.created), 2)
        self.assertEqual(host.helper.pid, 4002)

    def test_an_observation_that_fails_holds_and_says_why(self):
        host = self.with_helper()

        def failing():
            raise RuntimeError("fixture_observe_failed")

        host.helper.process.observe = failing
        record = self.iterate(host)
        self.assertEqual(record["helper"], {"status": "unknown", "started": False,
                                            "reason": "RuntimeError"})
        self.assertEqual(self.helper_removals, [])
        self.assertEqual(len(self.creation.created), 2)
        self.assertEqual(host.helper.pid, 4002)

    def test_the_dead_helper_row_is_released_before_a_replacement_is_created(self):
        host = self.with_helper()
        record = self.helper_died(host)
        # One removal, for the dead helper, while only the first two children
        # existed. The replacement is created after that.
        self.assertEqual(self.helper_removals, [(4002, 2)])
        self.assertEqual(record["helper"], {"status": "dead", "registry_removed": True,
                                            "registry_reason": None, "started": True,
                                            "pid": 4003})
        self.assertEqual(self.creation.created[2]["arguments"],
                         ["-m", "sentinel.adaptive.helper_host",
                          "--data-dir", str(self.directory),
                          "--profile", str(self.helper_profile)])
        self.assertEqual(host.helper.pid, 4003)
        self.assertEqual([item.pid for item in host.retired_helpers], [4002])
        # The guardian is untouched by any of it.
        self.assertEqual(record["guardian_status"], "alive")
        self.assertEqual(self.removals, [])

    def test_the_helper_budget_stops_a_replacement(self):
        host = self.with_helper(max_helpers=1)
        record = self.helper_died(host)
        # An exhausted budget does not keep the dead helper in the registry.
        self.assertEqual(self.helper_removals, [(4002, 2)])
        self.assertEqual(record["helper"],
                         {"status": "dead", "registry_removed": True, "registry_reason": None,
                          "started": False,
                          "reason": "supervisor_host_helper_budget_exhausted"})
        self.assertEqual(len(self.creation.created), 2)
        self.assertIsNone(host.helper)

    def test_a_failed_helper_removal_starts_nothing(self):
        """A row that is still there refuses the next helper start as occupied."""
        host = self.with_helper()
        self.helper_removal_result = (False, "legacy_infrastructure_registry_unavailable")
        record = self.helper_died(host)
        self.assertEqual(record["helper"],
                         {"status": "dead", "registry_removed": False,
                          "registry_reason": "legacy_infrastructure_registry_unavailable",
                          "started": False, "reason": "supervisor_host_helper_row_retained"})
        self.assertEqual(len(self.creation.created), 2)
        self.assertIsNotNone(host.helper)
        self.assertEqual(host.helper.pid, 4002)
        self.assertEqual(host.retired_helpers, [])

    def test_helper_registry_failure_retries_with_same_witness_even_at_budget_one(self):
        host = self.with_helper(max_helpers=1)
        original = host.helper
        self.helper_removal_result = (False, "fixture_registry_pending")
        self.assertFalse(self.helper_died(host)["helper"]["started"])
        self.assertIs(host.helper, original)
        self.assertFalse(self.iterate(host)["helper"]["started"])
        self.assertIs(host.helper, original)
        self.helper_removal_result = (True, None)
        result = self.iterate(host)
        self.assertEqual(result["helper"]["reason"], "supervisor_host_helper_budget_exhausted")
        self.assertTrue(result["helper"]["registry_removed"])
        self.assertEqual(self.helper_removals, [(original.pid, 2)] * 3)
        self.assertIsNone(host.helper)
        self.assertEqual(host.retired_helpers, [original])
        self.assertEqual(len(self.creation.created), 2)

    def test_helper_replacement_waits_for_failed_registry_cleanup_to_succeed(self):
        host = self.with_helper()
        original = host.helper
        self.helper_removal_result = (False, "fixture_registry_pending")
        self.helper_died(host)
        self.helper_removal_result = (True, None)
        result = self.iterate(host)
        self.assertTrue(result["helper"]["started"])
        self.assertEqual(self.helper_removals, [(original.pid, 2)] * 2)
        self.assertEqual(host.retired_helpers, [original])
        self.assertEqual(len(self.creation.created), 3)

    def test_an_absent_helper_row_does_not_stop_the_replacement(self):
        host = self.with_helper()
        self.helper_removal_result = (False, None)
        record = self.helper_died(host)
        self.assertEqual((record["helper"]["registry_removed"],
                          record["helper"]["registry_reason"],
                          record["helper"]["started"]), (False, None, True))
        self.assertEqual(len(self.creation.created), 3)

    def test_the_helper_is_observed_on_the_unattached_guardian_path(self):
        host = self.with_helper()
        self.observing(host, IdentityStatus.ALIVE)
        self.attach_error = "fixture_attach_unavailable"
        self.replace(host)
        self.assertIsNone(host.supervisor)
        held = self.iterate(host)
        self.assertEqual((held["guardian_status"], held["attached"]), ("unattached", False))
        self.assertEqual(held["helper"], {"status": "alive", "started": False})

    def test_close_leaves_the_helper_running_and_says_so(self):
        host = self.with_helper()
        record = host.close()
        self.assertEqual(record["helper_left_running"], True)
        self.assertNotIn(904, self.creation.closed)

    def test_close_releases_a_retired_helper_handle_once(self):
        host = self.with_helper()
        self.helper_died(host)
        record = host.close()
        self.assertIn(904, self.creation.closed)
        self.assertNotIn(host.helper.creation_handle, self.creation.closed)
        self.assertEqual((record["helper_left_running"], record["cleanup_errors"]), (True, []))

    def test_close_says_the_helper_is_gone_when_no_replacement_started(self):
        host = self.with_helper(max_helpers=1)
        self.helper_died(host)
        record = host.close()
        self.assertEqual(record["helper_left_running"], False)
        self.assertIn(904, self.creation.closed)

    def test_the_helper_options_default_to_off(self):
        parser = module.build_parser()
        default = parser.parse_args(["--data-dir", "d", "--journal-dir", "j"])
        self.assertEqual((default.helper_profile, default.max_helpers), (None, 1))
        chosen = parser.parse_args(["--data-dir", "d", "--journal-dir", "j",
                                    "--helper-profile", "p.json", "--max-helpers", "2"])
        self.assertEqual((chosen.helper_profile, chosen.max_helpers), ("p.json", 2))

    def test_main_refuses_a_helper_budget_below_one(self):
        records = []
        with patch.object(module, "emit", side_effect=records.append):
            code = module.main(["--data-dir", str(self.directory),
                                "--journal-dir", str(self.directory), "--max-helpers", "0"])
        self.assertEqual(code, EXIT_REFUSED)
        self.assertEqual(records[-1]["reason"], "supervisor_host_arguments_invalid")

    # --- the real attach path ---------------------------------------------

    def real_attach(self, error):
        """A started host whose _attach is the production method, with attach failing."""
        host = self.started()
        del host._attach
        return host, patch("sentinel.adaptive.supervisor.GuardianSupervisor.attach",
                           side_effect=error)

    def test_an_inventory_failure_after_capture_adopts_that_same_supervisor(self):
        captured = Supervisor(None, "captured")
        error = LifecycleError("supervisor_inventory_unavailable")
        error.supervisor_owner = captured
        host, attach = self.real_attach(error)
        with attach as attached:
            self.assertIs(host._attach(host.guardian), captured)
        # One attach call. The captured supervisor is kept, never rebuilt.
        self.assertEqual(attached.call_count, 1)
        self.assertEqual(host.unsettled_captures, [])

    def test_a_failed_capture_closes_its_partial_owner(self):
        partial = Supervisor(None, "partial")
        error = LifecycleError("recovery_capture_binding_unverified")
        error._recovery_owner = partial
        host, attach = self.real_attach(error)
        with attach, self.assertRaises(SupervisorHostRefused) as caught:
            host._attach(host.guardian)
        self.assertEqual((caught.exception.reason, caught.exception.detail),
                         ("supervisor_host_attach_unavailable", "recovery_capture_binding_unverified"))
        self.assertTrue(partial.closed)
        self.assertEqual(host.unsettled_captures, [])

    def test_a_partial_owner_that_will_not_close_is_kept_and_blocks_a_clean_exit(self):
        partial = Supervisor(None, "partial")
        partial.close_error = LifecycleError("recovery_custody_unsettled")
        error = LifecycleError("recovery_capture_binding_changed")
        error._recovery_owner = partial
        host, attach = self.real_attach(error)
        with attach, self.assertRaises(SupervisorHostRefused):
            host._attach(host.guardian)
        self.assertIs(host.unsettled_captures[0]["owner"], partial)
        record = host.close()
        self.assertEqual(record["unsettled_captures"],
                         [{"epoch": host.guardian.epoch, "reason": "recovery_custody_unsettled"}])

    def test_start_stays_up_unattached_when_the_first_attach_is_refused(self):
        host = self.build()
        self.attach_error = "recovery_capture_binding_unverified"
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC), \
                patch("sentinel.adaptive.store.LifecycleStore", return_value=host.store), \
                patch("sentinel.adaptive.recovery_journal.RecoveryJournal",
                      return_value=host.journal), \
                patch("sentinel.adaptive.supervisor_startup.SupervisorStartup", return_value=self.startup), \
                patch.object(reconciliation, "FinishedBarrierJanitor", return_value=self.janitor), \
                patch.object(module, "_Creation", return_value=self.creation), \
                patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                      side_effect=self.witness):
            record = host.start()
        self.assertEqual((record["attached"], record["attach_reason"]),
                         (False, "recovery_capture_binding_unverified"))
        self.assertIsNotNone(host.guardian)
        self.assertIsNone(host.supervisor)
        self.assertEqual(len(self.creation.created), 1)
        # The next iteration retries the attach against the same guardian.
        self.attach_error = None
        retried = host.run_once()
        self.assertEqual(retried["attached"], True)
        self.assertEqual(len(self.creation.created), 1)

    def test_main_retains_a_child_when_startup_is_refused_and_enters_resident_drain(self):
        class ObservationBoundary(BaseException):
            """End this synthetic observer without implying process cleanup."""

        host = self.started()
        original = host.guardian
        refusal = SupervisorHostRefused("supervisor_host_attach_unavailable", "fixture")
        records = []
        with patch.object(module, "SupervisorHost", return_value=host), \
                patch.object(host, "start", side_effect=refusal), \
                patch.object(host, "emit", side_effect=records.append), \
                patch.object(host, "supervise_until_stopped", side_effect=ObservationBoundary) as resident:
            with self.assertRaises(ObservationBoundary):
                module.main(["--data-dir", str(self.directory),
                             "--journal-dir", str(self.directory)])
        resident.assert_called_once_with()
        self.assertTrue(host.draining)
        self.assertIs(host.guardian, original)
        self.assertFalse(self.startup.closed)
        self.assertFalse(original.process.closed)
        self.assertEqual(records[-1]["guardian_created"], True)
        self.assertEqual(records[-1]["guardian_pid"], host.guardian.pid)
        self.assertEqual(records[-1]["guardian_epoch"], host.guardian.epoch)

    def test_main_reports_a_clean_refusal_when_no_child_was_created(self):
        host = self.build()
        refusal = SupervisorHostRefused("host_foreign_parent_job", None)
        records = []
        with patch.object(module, "SupervisorHost", return_value=host), \
                patch.object(host, "start", side_effect=refusal), \
                patch.object(host, "emit", side_effect=records.append):
            code = module.main(["--data-dir", str(self.directory),
                                "--journal-dir", str(self.directory)])
        self.assertEqual(code, EXIT_REFUSED)
        self.assertEqual(records[-1]["guardian_created"], False)
        self.assertEqual(records[-1]["unverified"], [])

    # --- shutdown ---------------------------------------------------------

    def test_close_leaves_the_guardian_running_and_says_so(self):
        host = self.started()
        record = host.close()
        self.assertTrue(record["guardian_left_running"])
        self.assertTrue(self.supervisors[0].closed)
        self.assertEqual(record["cleanup_errors"], [])

    def test_close_refuses_when_supervision_custody_is_unsettled(self):
        host = self.started()
        self.supervisors[0].close_error = RuntimeError("supervisor_custody_unsettled")
        with self.assertRaises(SupervisorHostRefused) as caught:
            host.close()
        self.assertEqual(caught.exception.reason, "supervisor_host_custody_unsettled")

    def test_a_retired_creation_handle_is_released_once_at_shutdown(self):
        host = self.started()
        self.replace(host)
        record = host.close()
        self.assertEqual(host.close(), record)
        self.assertEqual(self.creation.closed.count(902), 1)
        self.assertIn(902, self.creation.closed)
        self.assertNotIn(host.guardian.creation_handle, self.creation.closed)

    # --- startup and arguments -------------------------------------------

    def test_cold_start_creates_no_children_and_reconciles_barrier_every_tick(self):
        self.startup.fresh_error = LifecycleError("supervisor_startup_existing_obligations")
        self.janitor.result = reconciliation.ReconcileResult(False, True, False, "fixture_barrier_pending")
        host, record = self.start_through_main_path(helper_profile_path=self.helper_profile)
        self.assertEqual(record["state"], "COLD_RECOVERY_HOLD")
        self.assertFalse(record["guardian_created"])
        self.assertEqual(self.janitor.ticks, 1)
        self.assertEqual(self.startup.fresh_checks, 1)
        self.janitor.result = reconciliation.ReconcileResult(True, False, False, None, True)
        for _ in range(2):
            observed = host.run_once()
            self.assertEqual(observed["state"], "COLD_RECOVERY_HOLD")
            self.assertTrue(observed["barrier"]["complete"])
            self.assertFalse(observed["guardian_created"])
        self.assertEqual(self.janitor.ticks, 3)
        self.assertEqual(self.startup.fresh_checks, 1)
        self.assertEqual(self.creation.created, [])
        self.assertIsNone(host.guardian)
        self.assertIsNone(host.helper)

    def test_cold_hold_shutdown_reports_unresolved_recovery(self):
        self.startup.fresh_error = LifecycleError("supervisor_startup_existing_obligations")
        host, _ = self.start_through_main_path()
        record = host.close()
        self.assertEqual(record["cold_recovery_reason"], "supervisor_startup_existing_obligations")
        self.assertFalse(record["guardian_left_running"])
        self.assertEqual(self.creation.created, [])

    def test_transient_startup_inspection_retries_before_creating_any_child(self):
        self.startup.policy_pending = True
        self.startup.fresh_error = sqlite3.OperationalError("fixture read unavailable")
        host, record = self.start_through_main_path()
        self.assertEqual(record["state"], "COLD_RECOVERY_HOLD")
        self.assertFalse(record["guardian_created"])
        self.assertEqual(self.creation.created, [])
        self.assertEqual(self.startup.fresh_checks, 1)
        self.startup.fresh_error = None
        observed = host.run_once()
        self.assertEqual(observed["event"], "supervisor_host_iteration")
        self.assertTrue(observed["attached"])
        self.assertIsNone(host.cold_reason)
        self.assertEqual(self.startup.fresh_checks, 2)
        self.assertEqual(len(self.creation.created), 1)
        self.assertEqual(self.janitor.ticks, 2)

    def test_quarantined_startup_inspection_stays_cold_without_retry_or_children(self):
        self.startup.policy_pending = self.startup.policy_quarantined = True
        self.startup.policy_guard = object()
        self.startup.fresh_error = LifecycleError("fixture_policy_cleanup_unknown")
        host, record = self.start_through_main_path()
        retained = self.startup.policy_guard
        self.assertEqual(record["state"], "COLD_RECOVERY_HOLD")
        self.startup.fresh_error = None
        for _ in range(2):
            observed = host.run_once()
            self.assertEqual(observed["state"], "COLD_RECOVERY_HOLD")
            self.assertFalse(observed["guardian_created"])
        self.assertIs(self.startup.policy_guard, retained)
        self.assertEqual(self.startup.fresh_checks, 1)
        self.assertEqual(self.creation.created, [])
        self.assertEqual(self.janitor.ticks, 3)

    def test_start_refuses_on_this_host_before_creating_a_child(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        host = SupervisorHost(data_dir=self.directory, journal_dir=self.directory)
        with self.assertRaises(SupervisorHostRefused) as caught:
            host.start()
        self.assertEqual(caught.exception.reason, reason)
        self.assertIsNone(host.guardian)
        self.assertIsNone(host.store)

    def test_start_refuses_when_capability_is_unknown(self):
        unknown = HostCapabilityUnsupported("host_parent_job_membership_unknown", 6)
        host = SupervisorHost(data_dir=self.directory, journal_dir=self.directory)
        with patch.object(module, "read_host_capability", side_effect=unknown):
            with self.assertRaises(SupervisorHostRefused) as caught:
                host.start()
        self.assertEqual(caught.exception.reason, "host_parent_job_membership_unknown")

    def test_quoting_matches_the_documented_argv_rules(self):
        self.assertEqual(quote_argument("plain"), "plain")
        self.assertEqual(quote_argument("has space"), '"has space"')
        self.assertEqual(quote_argument("ends with\\"), r'"ends with\\"')
        self.assertEqual(quote_argument('quote"inside'), '"quote\\"inside"')


class SupervisorHostRegistryTests(unittest.TestCase):
    """Dead guardian row removal against a real isolated ledger and POLICY.

    The store, the POLICY coordinator and unregister_dead_infrastructure_locked
    are the production objects, and the ledger is a real SQLite file in a
    temporary directory. The guardian witness is a real VerifiedProcess over a
    synthetic identity backend that reports one status at a time, and process
    creation is the same synthetic backend as above. No process is started and
    no native handle is opened, so nothing here is evidence of Windows
    behaviour.
    """

    connection = lifecycle_fixtures.AdaptiveLifecycleTests.connection

    def setUp(self):
        lifecycle_fixtures.AdaptiveLifecycleTests.setUp(self)
        self.creation = Creation()
        self.supervisors = []
        self.witnesses = []
        with self.held():
            writer.initialize_registry_locked(self.store)

    @contextmanager
    def held(self):
        guard = self.store._policy.prepare(WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            yield guard

    def witness(self, handle, *, expected_pid, expected_logon_id):
        """A real VerifiedProcess over a synthetic backend; no handle is opened."""
        identity = ProcessIdentity(expected_pid, 134342315823996150 + expected_pid,
                                   expected_logon_id)
        backend = SyntheticIdentityBackend()
        process = VerifiedProcess(backend, handle, identity)
        self.addCleanup(process.close)
        self.witnesses.append((process, backend))
        return process

    def attach(self, guardian):
        supervisor = Supervisor(guardian, guardian.epoch)
        self.supervisors.append(supervisor)
        return supervisor

    def started(self, **overrides):
        arguments = dict(data_dir=self.directory, journal_dir=self.directory,
                         max_guardians=2, sleep=lambda seconds: None)
        arguments.update(overrides)
        host = SupervisorHost(**arguments)
        host.capability = SYNTHETIC
        host.store = self.store
        host.journal = SimpleNamespace(name="fixture-journal")
        host.creation = self.creation
        host.capability_logon = lambda: WRAPPER.logon_id
        host._attach = self.attach
        # This suite exercises the production retained registry operation;
        # startup/rollover capability proofs have independent isolated suites.
        host.startup = Startup()
        host.startup.acquire()
        host._rollover_epoch = rollover_fixture
        host._capture_guardian_creation = lambda handle, pid, epoch: CreationWitness(
            self.witness(handle, expected_pid=pid, expected_logon_id=WRAPPER.logon_id), epoch)
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            host.guardian = host._start_guardian()
            host.supervisor = host._attach(host.guardian)
            if host.helper_profile_path is not None:
                host.helper = host._start_helper()
        self.process, self.backend = self.witnesses[0]
        return host

    def with_helper(self, **overrides):
        """A started host that also supervises one helper child."""
        overrides.setdefault("helper_profile_path", self.directory / "helper-profile.json")
        overrides.setdefault("max_helpers", 2)
        host = self.started(**overrides)
        self.helper_process, self.helper_backend = self.witnesses[-1]
        return host

    def register(self, process, role="guardian"):
        """What the child process itself writes at startup."""
        with self.held():
            self.assertTrue(writer.register_infrastructure_locked(self.store, role, process))

    def rows(self):
        return [(row["role"], row["pid"]) for row in self.connection().execute(
            "SELECT role,pid FROM adaptive_infrastructure ORDER BY pid")]

    def runtime(self):
        return dict(self.connection().execute(
            "SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def dead(self, host):
        """The supervisor reports a verified death and the witness agrees."""
        self.supervisors[-1].status = IdentityStatus.DEAD
        self.backend.status = IdentityStatus.DEAD
        return self.iterate(host)

    def iterate(self, host):
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            return host.run_once()

    def test_initial_create_and_final_fresh_check_share_the_same_policy_guard(self):
        host = SupervisorHost(data_dir=self.directory, journal_dir=self.directory)
        host.store, host.creation = self.store, self.creation
        host.capability_logon = lambda: WRAPPER.logon_id
        host.startup = Startup()
        host.startup.acquire()
        with self.held() as guard:
            host.startup.binding = guard.binding
        observed = []
        def fresh():
            host.startup.assert_held()
            active = self.store._policy.assert_held()
            self.assertTrue(self.policy.active)
            observed.append(("fresh", active))
        host.startup.assert_fresh_locked = fresh
        host._capture_guardian_creation = lambda handle, pid, epoch: CreationWitness(
            self.witness(handle, expected_pid=pid, expected_logon_id=WRAPPER.logon_id), epoch)
        create = self.creation.create
        def creating(*args):
            active = self.store._policy.assert_held()
            self.assertTrue(self.policy.active)
            observed.append(("create", active))
            return create(*args)
        with patch.object(self.creation, "create", side_effect=creating):
            guardian = host._start_initial_guardian()
        self.assertEqual([name for name, _ in observed], ["fresh", "create"])
        self.assertIs(observed[0][1], observed[1][1])
        self.assertEqual(guardian.pid, 4001)
        self.assertFalse(self.policy.active)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_initial_policy_exit_failure_keeps_exact_child_guard_and_created_report(self):
        host = SupervisorHost(data_dir=self.directory, journal_dir=self.directory)
        host.store, host.creation = self.store, self.creation
        host.capability_logon = lambda: WRAPPER.logon_id
        host.startup = Startup()
        host.startup.acquire()
        with self.held() as guard:
            host.startup.binding = guard.binding
        host.startup.assert_fresh_locked = self.store._policy.assert_held
        host._capture_guardian_creation = lambda handle, pid, epoch: CreationWitness(
            self.witness(handle, expected_pid=pid, expected_logon_id=WRAPPER.logon_id), epoch)
        provider_hold = self.policy.hold

        @contextmanager
        def uncertain_exit(binding, *, timeout_ms):
            with provider_hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            # The fixture releases its lock, then reports an uncertain native
            # exit. Production POLICY must retain its nonce and exact guard.
            raise LifecycleError("fixture_policy_cleanup_unknown")

        with patch.object(self.policy, "hold", side_effect=uncertain_exit) as provider, \
                patch.object(self.store._policy, "hold", wraps=self.store._policy.hold) as held:
            record = host._finish_startup(None)
            original = host.guardian
            retained = held.call_args.args[0]
            self.assertEqual(record["state"], "COLD_RECOVERY_HOLD")
            self.assertTrue(record["guardian_created"])
            self.assertIsNotNone(original)
            self.assertIs(original.process, self.witnesses[0][0])
            self.assertIs(original.creation_witness.process, original.process)
            self.assertEqual(original.creation_handle, 902)
            self.assertIs(host._initial_start_operation.guard, retained)
            self.assertTrue(host._initial_start_result.quarantined)
            self.assertEqual(self.runtime()["policy_entry_nonce"], retained.nonce)
            retry = host.run_once()
            self.assertEqual(retry["state"], "COLD_RECOVERY_HOLD")
            self.assertTrue(retry["guardian_created"])
            self.assertIs(host.guardian, original)
            self.assertIs(host._initial_start_operation.guard, retained)
            self.assertEqual(provider.call_count, 1)
            self.assertEqual(held.call_count, 1)
        self.assertEqual(len(self.creation.created), 1)
        self.assertNotIn(original.creation_handle, self.creation.closed)
        with self.assertRaisesRegex(SupervisorHostRefused, "supervisor_host_policy_operation_pending"):
            host.close()
        self.assertFalse(host.startup.closed)

    def early_dead_unattached(self):
        """An original creation witness died before any Job scope existed."""
        host = self.started(max_guardians=1)
        with self.held() as guard:
            host.startup.binding = guard.binding
        self.backend.status = IdentityStatus.DEAD
        host.supervisor = None
        return host

    @contextmanager
    def empty_inspection_fault(self, error):
        """Fail only the first empty-scope read, after entering real POLICY."""
        connection = self.store._connection
        attempts = []
        store = self.store

        class FaultConnection:
            def __init__(self, actual):
                self.actual = actual

            def __getattr__(self, name):
                return getattr(self.actual, name)

            def execute(self, statement, *args, **kwargs):
                if "FROM managed_executions WHERE job_name" in statement:
                    attempts.append(store._policy.assert_held())
                    if len(attempts) == 1:
                        raise error
                return self.actual.execute(statement, *args, **kwargs)

        @contextmanager
        def faulted():
            with connection() as conn:
                yield FaultConnection(conn)

        with patch.object(self.store, "_connection", side_effect=faulted):
            yield attempts

    def test_empty_inspection_retries_original_guard_before_a_now_successful_attach(self):
        host = self.early_dead_unattached()
        original = host.guardian
        refused = SupervisorHostRefused("supervisor_host_attach_unavailable", "fixture")
        settled = {"started": False, "reason": "fixture_replacement_not_requested"}
        with patch.object(host, "_attach_created", side_effect=refused) as attach, \
                patch.object(host, "_replace", return_value=settled) as replace, \
                patch.object(self.store._policy, "prepare", wraps=self.store._policy.prepare) as prepare, \
                patch.object(self.store._policy, "hold", wraps=self.store._policy.hold) as held, \
                self.empty_inspection_fault(sqlite3.OperationalError("fixture transient read")) as reads:
            first = host.run_once()
            retained = host._empty_check.guard
            self.assertFalse(first["attached"])
            self.assertIsNone(first["replacement"])
            self.assertIsNotNone(retained)
            self.assertIs(reads[0], retained)
            self.assertEqual(self.runtime()["policy_entry_nonce"], retained.nonce)
            self.assertTrue(host._empty_result.pending)
            self.assertFalse(host._empty_result.quarantined)
            replace.assert_not_called()
            # If the next tick attached first, it could abandon the earlier
            # guard. Even a now-successful attach must wait for its settlement.
            attach.side_effect = None
            attach.return_value = Supervisor(original, original.epoch)
            second = host.run_once()
            self.assertEqual(second["replacement"], settled)
            self.assertTrue(host._empty_result.complete)
            self.assertIsNone(host._empty_check.guard)
            self.assertTrue(host._guardian_settled)
            self.assertEqual(prepare.call_count, 1)
            self.assertEqual(held.call_count, 2)
            self.assertTrue(all(call.args[0] is retained for call in held.call_args_list))
            self.assertEqual(reads, [retained, retained])
            self.assertEqual(attach.call_count, 1)
            replace.assert_called_once_with()
        self.assertIs(host.guardian, original)
        self.assertIsNone(host.supervisor)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(len(self.creation.created), 1)

    def test_unknown_empty_inspection_cleanup_never_reenters_or_attaches(self):
        host = self.early_dead_unattached()
        refused = SupervisorHostRefused("supervisor_host_attach_unavailable", "fixture")
        provider_hold = self.policy.hold

        @contextmanager
        def uncertain_exit(binding, *, timeout_ms):
            with provider_hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise LifecycleError("fixture_policy_cleanup_unknown")

        with patch.object(host, "_attach_created", side_effect=refused) as attach, \
                patch.object(self.policy, "hold", side_effect=uncertain_exit) as provider, \
                patch.object(self.store._policy, "prepare", wraps=self.store._policy.prepare) as prepare:
            first = host.run_once()
            retained = host._empty_check.guard
            self.assertIsNone(first["replacement"])
            self.assertIsNotNone(retained)
            self.assertTrue(host._empty_result.quarantined)
            attach.side_effect = None
            attach.return_value = Supervisor(host.guardian, host.guardian.epoch)
            for _ in range(2):
                retry = host.run_once()
                self.assertEqual(retry["reason"], "supervisor_host_empty_inspection_pending")
                self.assertIsNone(retry["replacement"])
                self.assertIs(host._empty_check.guard, retained)
            self.assertEqual(prepare.call_count, 1)
            self.assertEqual(provider.call_count, 1)
            self.assertEqual(attach.call_count, 1)
        self.assertEqual(self.runtime()["policy_entry_nonce"], retained.nonce)
        self.assertIsNone(host.supervisor)
        self.assertEqual(len(self.creation.created), 1)
        with self.assertRaisesRegex(SupervisorHostRefused, "supervisor_host_policy_operation_pending"):
            host.close()
        self.assertFalse(host.startup.closed)

    def test_interrupted_empty_inspection_retains_guard_and_blocks_close_without_result(self):
        host = self.early_dead_unattached()
        with self.empty_inspection_fault(KeyboardInterrupt()) as reads:
            with self.assertRaises(KeyboardInterrupt):
                host._unstarted_guardian_empty()
        retained = host._empty_check.guard
        self.assertIsNotNone(retained)
        self.assertIs(reads[0], retained)
        self.assertIsNone(host._empty_result)
        self.assertTrue(host._empty_check.pending)
        self.assertEqual(self.runtime()["policy_entry_nonce"], retained.nonce)
        with self.assertRaisesRegex(SupervisorHostRefused, "supervisor_host_policy_operation_pending"):
            host.close()
        self.assertIs(host._empty_check.guard, retained)
        self.assertFalse(host.startup.closed)
        self.assertNotIn(host.guardian.creation_handle, self.creation.closed)
        with patch.object(self.store._policy, "prepare") as prepare, \
                patch.object(self.store._policy, "hold") as held:
            self.assertFalse(host._unstarted_guardian_empty())
        prepare.assert_not_called()
        held.assert_not_called()
        self.assertTrue(host._empty_result.quarantined)

    def test_a_verified_death_removes_the_guardian_row_and_reports_it(self):
        host = self.started()
        self.register(self.process)
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        revision = self.runtime()["registry_revision"]
        record = self.dead(host)
        self.assertEqual((record["replacement"]["started"],
                          record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]), (True, True, None))
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.runtime()["registry_revision"], revision + 1)
        # The POLICY scope is entered and released around that one call.
        self.assertFalse(self.policy.active)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_an_absent_row_is_reported_as_not_removed_with_no_reason(self):
        host = self.started()
        record = self.dead(host)
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]), (False, None))
        self.assertEqual(self.rows(), [])

    def test_an_exhausted_guardian_budget_still_removes_the_row(self):
        host = self.started(max_guardians=1)
        self.register(self.process)
        record = self.dead(host)
        self.assertEqual(record["replacement"],
                         {"started": False, "reason": "supervisor_host_guardian_budget_exhausted",
                          "registry_removed": True, "registry_reason": None})
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.creation.created), 1)

    def test_the_policy_mutex_is_held_while_the_row_is_removed(self):
        host = self.started()
        self.register(self.process)
        removal = writer.unregister_dead_infrastructure_locked
        observed = []

        def recording(store, role, process):
            observed.append((role, self.policy.active,
                             store._policy.current_guard() is not None))
            return removal(store, role, process)

        with patch.object(reconciliation, "unregister_dead_infrastructure_locked", recording):
            record = self.dead(host)
        self.assertEqual(observed, [("guardian", True, True)])
        self.assertTrue(record["replacement"]["registry_removed"])
        self.assertEqual(self.rows(), [])

    def test_a_removal_that_raises_retains_owner_and_retries_before_replacement(self):
        host = self.started()
        self.register(self.process)
        previous = host.guardian
        error = writer.LegacyMutationError("legacy_infrastructure_registry_unavailable")
        with patch.object(reconciliation, "unregister_dead_infrastructure_locked", side_effect=error):
            record = self.dead(host)
        self.assertFalse(record["replacement"]["started"])
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]),
                         (False, "legacy_infrastructure_registry_unavailable"))
        self.assertEqual(self.rows(), [("guardian", previous.pid)])
        self.assertEqual(len(self.creation.created), 1)
        self.assertIs(host.guardian, previous)
        pending = host._registry_retirements[("guardian", id(previous))]
        retried = self.iterate(host)
        self.assertTrue(retried["replacement"]["started"])
        self.assertIs(host._registry_retirements[("guardian", id(previous))], pending)
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.creation.created), 2)

    def test_pending_registry_retirement_blocks_close_until_exact_retry_settles(self):
        host = self.started(max_guardians=1)
        self.register(self.process)
        original = host.guardian
        error = writer.LegacyMutationError("legacy_infrastructure_registry_unavailable")
        with patch.object(reconciliation, "unregister_dead_infrastructure_locked", side_effect=error):
            result = self.dead(host)
        self.assertFalse(result["replacement"]["started"])
        with self.assertRaisesRegex(SupervisorHostRefused, "supervisor_host_registry_retirement_pending"):
            host.close()
        self.assertEqual(self.process.observe().status, IdentityStatus.DEAD)
        self.assertNotIn(original.creation_handle, self.creation.closed)
        self.assertFalse(host.startup.closed)
        self.assertEqual(self.rows(), [("guardian", original.pid)])
        retried = self.iterate(host)
        self.assertEqual(retried["replacement"]["reason"], "supervisor_host_guardian_budget_exhausted")
        self.assertTrue(retried["replacement"]["registry_removed"])
        self.assertEqual(self.rows(), [])
        closed = host.close()
        self.assertFalse(closed["guardian_left_running"])
        self.assertEqual(closed["cleanup_errors"], [])
        self.assertIn(original.creation_handle, self.creation.closed)
        self.assertEqual(len(self.creation.created), 1)

    def test_a_death_the_witness_does_not_confirm_removes_nothing(self):
        """Retained retirement requires independent native death before SQL.

        A supervisor result cannot replace its original witness. This refusal
        does not create a replacement or occupy the shared POLICY scope.
        """
        host = self.started()
        self.register(self.process)
        previous = host.guardian
        self.supervisors[-1].status = IdentityStatus.DEAD
        record = self.iterate(host)
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]),
                         (False, "infrastructure_retirement_death_unverified"))
        self.assertEqual(self.rows(), [("guardian", previous.pid)])
        self.assertFalse(record["replacement"]["started"])
        self.assertEqual(len(self.creation.created), 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        # The scope is free, so the next owner can take it.
        with self.held():
            pass

    def test_refused_removal_waits_for_retained_death_then_replacement_can_register(self):
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].status = IdentityStatus.DEAD
        record = self.iterate(host)
        self.assertEqual(record["replacement"]["registry_reason"],
                         "infrastructure_retirement_death_unverified")
        self.assertEqual(len(self.creation.created), 1)
        self.backend.status = IdentityStatus.DEAD
        self.assertTrue(self.iterate(host)["replacement"]["started"])
        # Only after the original row is retired may the replacement register.
        replacement, _ = self.witnesses[-1]
        guard = self.store._policy.prepare(WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            self.assertTrue(writer.register_infrastructure_locked(self.store, "guardian",
                                                                  replacement))
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_a_failed_close_attempts_no_removal_and_the_row_stays(self):
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].close_error = LifecycleError("supervisor_custody_unsettled")
        with patch.object(reconciliation, "unregister_dead_infrastructure_locked") as removal:
            record = self.dead(host)
        removal.assert_not_called()
        self.assertEqual(record["replacement"], {"started": False,
                                                 "reason": "supervisor_custody_unsettled"})
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    # --- the helper row ----------------------------------------------------

    def helper_died(self, host):
        """The retained helper witness reports a verified death."""
        self.helper_backend.status = IdentityStatus.DEAD
        return self.iterate(host)

    def test_a_verified_helper_death_removes_the_helper_row_and_frees_the_scope(self):
        host = self.with_helper()
        self.register(self.process)
        self.register(self.helper_process, "helper")
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid),
                                       ("helper", self.helper_process.identity.pid)])
        revision = self.runtime()["registry_revision"]
        record = self.helper_died(host)
        self.assertEqual((record["helper"]["registry_removed"],
                          record["helper"]["registry_reason"],
                          record["helper"]["started"]), (True, None, True))
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        self.assertEqual(self.runtime()["registry_revision"], revision + 1)
        # The POLICY scope is entered and released around that one call.
        self.assertFalse(self.policy.active)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        # The property the release exists for: the replacement helper the host
        # just created can register itself.
        replacement, _ = self.witnesses[-1]
        self.register(replacement, "helper")
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid),
                                       ("helper", replacement.identity.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_a_helper_death_the_witness_does_not_confirm_removes_nothing(self):
        """The production function re-verifies death; this host adds no check.

        The witness reports DEAD to the iteration and then reports the helper
        alive again to the writer, which is the only way the two can disagree
        when there is one witness. That refusal is decided before the writer's
        transaction, so it is a clean rejection and POLICY releases its durable
        entry nonce.
        """
        host = self.with_helper()
        self.register(self.helper_process, "helper")
        removal = writer.unregister_dead_infrastructure_locked

        def revived(store, role, process):
            self.helper_backend.status = IdentityStatus.ALIVE
            return removal(store, role, process)

        with patch.object(reconciliation, "unregister_dead_infrastructure_locked", revived):
            record = self.helper_died(host)
        self.assertEqual(record["helper"],
                         {"status": "dead", "registry_removed": False,
                          "registry_reason": "legacy_infrastructure_death_unverified",
                          "started": False, "reason": "supervisor_host_helper_row_retained"})
        # The row stays, so no replacement was started that would refuse as
        # occupied, and the scope is free for the next owner.
        self.assertEqual(self.rows(), [("helper", self.helper_process.identity.pid)])
        self.assertEqual(len(self.creation.created), 2)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        with self.held():
            pass

    def test_a_helper_witness_that_is_not_dead_removes_nothing(self):
        host = self.with_helper()
        self.register(self.helper_process, "helper")
        with patch.object(reconciliation, "unregister_dead_infrastructure_locked") as removal:
            record = self.iterate(host)
        removal.assert_not_called()
        self.assertEqual(record["helper"], {"status": "alive", "started": False})
        self.assertEqual(self.rows(), [("helper", self.helper_process.identity.pid)])
        self.assertEqual(len(self.creation.created), 2)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_unknown_never_reaches_the_removal(self):
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].status = IdentityStatus.UNKNOWN
        with patch.object(reconciliation, "unregister_dead_infrastructure_locked") as removal:
            record = self.iterate(host)
        removal.assert_not_called()
        self.assertIsNone(record["replacement"])
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])


class SupervisorHostSubprocessTests(unittest.TestCase):
    def run_host(self, *arguments):
        return subprocess.run([sys.executable, "-m", "sentinel.adaptive.supervisor_host", *arguments],
                              cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

    def test_help_is_available(self):
        result = self.run_host("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--journal-dir", result.stdout)

    def test_a_start_on_an_isolated_data_directory_refuses_with_a_typed_reason(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_host("--data-dir", directory, "--journal-dir", directory,
                                   "--iterations", "1")
        self.assertEqual(result.returncode, EXIT_REFUSED)
        record = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(record["event"], "supervisor_host_refused")
        self.assertEqual(record["reason"], reason)


if __name__ == "__main__":
    unittest.main()
