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
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import legacy_writer as writer
from sentinel.adaptive import supervisor_host as module
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.host_authority import HostCapabilityUnsupported
from sentinel.adaptive.identity import VerifiedProcess
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
        self.close_error = None

    def create(self, executable, arguments, cwd):
        if self.create_error is not None:
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

    def tick(self, *, now=None):
        if self.closed:
            raise AssertionError("closed supervisor ticked")
        self.ticks += 1
        return supervision(self.status)

    def close(self):
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
        self.removals = []
        self.removal_result = (True, None)

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
        # The registry removal itself runs against a real ledger in
        # SupervisorHostRegistryTests below.
        host._unregister = self.unregister
        return host

    def unregister(self, guardian):
        # How many children exist at this point records the ordering: the row
        # is released before any replacement is created.
        self.removals.append((guardian.epoch, len(self.creation.created)))
        return self.removal_result

    def attach(self, guardian):
        if self.attach_error is not None:
            raise SupervisorHostRefused("supervisor_host_attach_unavailable", self.attach_error)
        supervisor = Supervisor(guardian, guardian.epoch)
        self.supervisors.append(supervisor)
        return supervisor

    def witness(self, handle, *, expected_pid, expected_logon_id):
        if self.witness_error is not None:
            raise self.witness_error
        return SimpleNamespace(handle=handle, pid=expected_pid, logon=expected_logon_id)

    def started(self, **overrides):
        host = self.build(**overrides)
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            host.guardian = host._start_guardian()
            host.supervisor = host._attach(host.guardian)
        return host

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
        self.removal_result = (False, "legacy_infrastructure_registry_unavailable")
        record = self.replace(host)
        self.assertEqual(record["replacement"],
                         {"started": True, "attached": False,
                          "reason": "supervisor_host_attach_unavailable",
                          "guardian_epoch": host.guardian.epoch,
                          "registry_removed": False,
                          "registry_reason": "legacy_infrastructure_registry_unavailable"})

    def test_a_reused_epoch_is_refused_before_a_child_exists(self):
        host = self.started()
        with patch.object(module, "mint_guardian_epoch", return_value=host.guardian.epoch):
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
        # The fixture witness cannot be observed, so nothing is claimed about it.
        self.assertEqual(held["guardian_observed"], "unknown")
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

    def test_main_names_a_child_that_exists_when_startup_is_refused(self):
        host = self.started()
        refusal = SupervisorHostRefused("supervisor_host_attach_unavailable", "fixture")
        records = []
        with patch.object(module, "SupervisorHost", return_value=host), \
                patch.object(host, "start", side_effect=refusal), \
                patch.object(module, "emit", side_effect=records.append):
            code = module.main(["--data-dir", str(self.directory),
                                "--journal-dir", str(self.directory)])
        self.assertEqual(code, EXIT_UNSETTLED)
        self.assertEqual(records[-1]["guardian_created"], True)
        self.assertEqual(records[-1]["guardian_pid"], host.guardian.pid)
        self.assertEqual(records[-1]["guardian_epoch"], host.guardian.epoch)

    def test_main_reports_a_clean_refusal_when_no_child_was_created(self):
        host = self.build()
        refusal = SupervisorHostRefused("host_foreign_parent_job", None)
        records = []
        with patch.object(module, "SupervisorHost", return_value=host), \
                patch.object(host, "start", side_effect=refusal), \
                patch.object(module, "emit", side_effect=records.append):
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
        host.close()
        self.assertIn(902, self.creation.closed)
        self.assertNotIn(host.guardian.creation_handle, self.creation.closed)

    # --- startup and arguments -------------------------------------------

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
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle",
                   side_effect=self.witness):
            host.guardian = host._start_guardian()
            host.supervisor = host._attach(host.guardian)
        self.process, self.backend = self.witnesses[0]
        return host

    def register(self, process):
        """What the guardian process itself writes at startup."""
        with self.held():
            self.assertTrue(writer.register_infrastructure_locked(self.store, "guardian", process))

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

        with patch.object(writer, "unregister_dead_infrastructure_locked", recording):
            record = self.dead(host)
        self.assertEqual(observed, [("guardian", True, True)])
        self.assertTrue(record["replacement"]["registry_removed"])
        self.assertEqual(self.rows(), [])

    def test_a_removal_that_raises_is_reported_and_the_replacement_still_starts(self):
        host = self.started()
        self.register(self.process)
        previous = host.guardian
        error = writer.LegacyMutationError("legacy_infrastructure_registry_unavailable")
        with patch.object(writer, "unregister_dead_infrastructure_locked", side_effect=error):
            record = self.dead(host)
        self.assertEqual((record["replacement"]["started"], record["replacement"]["attached"]),
                         (True, True))
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]),
                         (False, "legacy_infrastructure_registry_unavailable"))
        self.assertEqual(self.rows(), [("guardian", previous.pid)])
        self.assertEqual(len(self.creation.created), 2)

    def test_a_death_the_witness_does_not_confirm_removes_nothing(self):
        """The production function re-verifies death; this host adds no check.

        The supervisor fixture reports DEAD while the retained witness still
        reports the guardian alive, which only the removal itself can catch.
        That refusal is decided before the writer's transaction, so it is a
        clean rejection and POLICY releases its durable entry nonce. This is an
        intended behaviour change: the earlier revision of this test pinned the
        retained nonce, which wedged every later POLICY user of the data
        directory.
        """
        host = self.started()
        self.register(self.process)
        previous = host.guardian
        self.supervisors[-1].status = IdentityStatus.DEAD
        record = self.iterate(host)
        self.assertEqual((record["replacement"]["registry_removed"],
                          record["replacement"]["registry_reason"]),
                         (False, "legacy_infrastructure_death_unverified"))
        self.assertEqual(self.rows(), [("guardian", previous.pid)])
        self.assertEqual(record["replacement"]["started"], True)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        # The scope is free, so the next owner can take it.
        with self.held():
            pass

    def test_a_refused_removal_leaves_the_next_guardian_able_to_register(self):
        """The property the release exists for, through the real writer."""
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].status = IdentityStatus.DEAD
        record = self.iterate(host)
        self.assertEqual(record["replacement"]["registry_reason"],
                         "legacy_infrastructure_death_unverified")
        # What the replacement guardian process does at its own startup.
        replacement, _ = self.witnesses[-1]
        guard = self.store._policy.prepare(WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            self.assertTrue(writer.register_infrastructure_locked(self.store, "guardian",
                                                                  replacement))
        self.assertEqual(self.rows(), [("guardian", host.retired[0].pid),
                                       ("guardian", host.guardian.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_a_failed_close_attempts_no_removal_and_the_row_stays(self):
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].close_error = LifecycleError("supervisor_custody_unsettled")
        with patch.object(writer, "unregister_dead_infrastructure_locked") as removal:
            record = self.dead(host)
        removal.assert_not_called()
        self.assertEqual(record["replacement"], {"started": False,
                                                 "reason": "supervisor_custody_unsettled"})
        self.assertEqual(self.rows(), [("guardian", host.guardian.pid)])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_unknown_never_reaches_the_removal(self):
        host = self.started()
        self.register(self.process)
        self.supervisors[-1].status = IdentityStatus.UNKNOWN
        with patch.object(writer, "unregister_dead_infrastructure_locked") as removal:
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
