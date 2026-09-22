"""Cold-start production checks against real isolated SQLite and journals.

VerifiedProcess uses a synthetic handle backend and mutexes are explicit fixture
objects. No process is started/opened by PID or controlled, and these tests do
not prove Windows singleton exclusion, native recovery or promotion readiness.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.policy import PolicyBinding, PolicyError
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor_startup import SupervisorStartup, supervisor_instance_binding
from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_guardian_launch import ProcessBackend


LOGON = "S-1-5-5-31-41"
CURRENT = ProcessIdentity(os.getpid(), 134343072000000301, LOGON)


class Mutex:
    """In-process lease fixture; no native mutex and no simulated death proof."""
    def __init__(self, owner, logon, instance):
        self.owner, self.binding = owner, PolicyBinding(instance, logon)
        self.name = self.binding.name
        self.acquired = self.closed = False
        self.abandoned = False
        self.wait_error = self.release_error = self.close_error = None
        self.on_enter = None
        self.enters = self.releases = self.closes = 0

    def acquire(self, *, timeout_ms):
        assert timeout_ms == 250
        return self

    def __enter__(self):
        self.enters += 1
        if self.wait_error is not None:
            raise self.wait_error
        if self.name in self.owner.held:
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.owner.held[self.name] = self
        self.acquired = True
        if self.on_enter is not None:
            self.on_enter()
        return PolicyMutexLease(self.name, self.binding.instance_id, self.binding.logon_id, self.abandoned)

    def __exit__(self, kind, primary, traceback):
        self.releases += 1
        if self.release_error is not None:
            raise self.release_error
        assert self.acquired and not self.closed
        del self.owner.held[self.name]
        self.acquired = False
        return False

    def close(self):
        self.closes += 1
        assert not self.acquired and not self.closed
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class SupervisorStartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        self.policy = FixturePolicyProvider(LOGON)
        LifecycleStore(self.db, policy_provider=self.policy)
        self.store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        self.journal = RecoveryJournal(self.directory)
        self.native = ProcessBackend()
        self.current = self.native.process(CURRENT)
        self.held, self.mutexes = {}, []
        self.configure_mutex = None

    def sql(self, statement, values=()):
        with closing(sqlite3.connect(self.db)) as conn:
            with conn:
                return conn.execute(statement, values).fetchall()

    def runtime(self):
        with self.store._connection() as conn:
            return dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())

    def mutex_factory(self, logon, instance):
        mutex = Mutex(self, logon, instance)
        self.mutexes.append(mutex)
        if self.configure_mutex is not None:
            self.configure_mutex(mutex)
        return mutex

    def owner(self, *, current=None, mutex_factory=None):
        result = SupervisorStartup(self.store, self.journal, current=current or self.current,
                                   mutex_factory=mutex_factory or self.mutex_factory)
        self.addCleanup(self.cleanup_owner, result)
        return result

    @staticmethod
    def cleanup_owner(owner):
        # Deliberate ambiguous fixture failures must remain quarantined. All
        # objects here are synthetic; leaving one is no real handle leak.
        try:
            owner.close()
        except (LifecycleError, NativePolicyMutexError, RuntimeError):
            pass

    def fresh(self):
        owner = self.owner().acquire()
        owner.assert_fresh()
        return owner

    def add_infrastructure(self, owner, role="guardian", pid=9001, **overrides):
        owner.assert_fresh()  # Explicit registry initialization on empty state.
        values = dict(role=role, pid=pid, birth=str(CURRENT.created_filetime_100ns + pid), logon=LOGON)
        values.update(overrides)
        self.sql("INSERT INTO adaptive_infrastructure VALUES(?,?,?,?,1)",
                 (values["role"], values["pid"], values["birth"], values["logon"]))

    def test_fresh_ledger_pins_binding_retains_exact_self_and_mutex_until_close(self):
        owner = self.fresh()
        self.assertNotEqual(owner._current._handle, self.current._handle)
        self.assertEqual(owner._current.identity, CURRENT)
        self.assertTrue(self.mutexes[0].acquired)
        self.assertEqual(owner.binding.instance_id, self.runtime()["policy_instance_id"])
        self.assertEqual(owner.instance_binding, supervisor_instance_binding(owner.binding))
        self.assertNotEqual(owner.instance_binding, owner.binding)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        owner.assert_held()
        owner.close()
        owner.close()
        self.assertEqual((self.mutexes[0].releases, self.mutexes[0].closes), (1, 1))
        self.assertFalse(self.held)

    def test_competing_hosts_cannot_both_hold_singleton(self):
        first = self.fresh()
        second = self.owner()
        with self.assertRaisesRegex(NativePolicyMutexError, "timeout"):
            second.acquire()
        self.assertEqual(self.mutexes[0].name, self.mutexes[1].name)
        second.close()
        first.assert_held()
        first.close()
        third = self.fresh()
        third.assert_held()

    def test_instance_namespace_changes_with_policy_or_logon(self):
        owner = self.fresh()
        self.assertNotEqual(owner.instance_binding, supervisor_instance_binding(PolicyBinding(str(uuid4()), LOGON)))
        self.assertNotEqual(owner.instance_binding, supervisor_instance_binding(PolicyBinding(owner.binding.instance_id, "S-1-5-5-31-42")))

    def test_acquire_cannot_be_repeated_even_after_timeout(self):
        self.fresh()
        owner = self.owner()
        with self.assertRaises(NativePolicyMutexError):
            owner.acquire()
        with self.assertRaisesRegex(LifecycleError, "acquire_repeated"):
            owner.acquire()

    def test_closed_and_foreign_thread_owners_have_no_authority(self):
        owner = self.fresh()
        errors = []
        def foreign():
            for operation in (owner.assert_held, owner.close):
                try:
                    operation()
                except LifecycleError as error:
                    errors.append(str(error))
        thread = threading.Thread(target=foreign)
        thread.start()
        thread.join()
        self.assertEqual(errors, ["supervisor_startup_foreign_owner"] * 2)
        owner.assert_held()
        owner.close()
        with self.assertRaisesRegex(LifecycleError, "mutex_unverified"):
            owner.assert_held()

    def test_exact_current_identity_must_be_alive_and_actual_self(self):
        for identity, status in ((replace(CURRENT, pid=CURRENT.pid + 1), IdentityStatus.ALIVE),
                                 (CURRENT, IdentityStatus.DEAD), (CURRENT, IdentityStatus.UNKNOWN)):
            with self.subTest(identity=identity, status=status):
                native = ProcessBackend()
                current = native.process(identity)
                native.objects[identity].status = status
                owner = self.owner(current=current)
                with self.assertRaisesRegex(LifecycleError, "current_unverified"):
                    owner.acquire()
        self.assertFalse(self.mutexes)

    def test_abandonment_permits_inspection_but_never_fresh_creation_authority(self):
        self.configure_mutex = lambda mutex: setattr(mutex, "abandoned", True)
        owner = self.owner().acquire()
        with self.assertRaisesRegex(LifecycleError, "mutex_abandoned"):
            owner.assert_fresh()
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        with self.assertRaisesRegex(LifecycleError, "mutex_abandoned"):
            owner.assert_held()
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_infrastructure"), [(0,)])

    def test_each_existing_infrastructure_role_is_cold_hold_without_pid_open(self):
        owner = self.fresh()
        for role in ("guardian", "helper", "supervisor"):
            with self.subTest(role=role):
                self.add_infrastructure(owner, role=role)
                with patch.object(VerifiedProcess, "open", side_effect=AssertionError("no PID adoption")):
                    with self.assertRaisesRegex(LifecycleError, "cold_adoption_unsupported"):
                        owner.assert_fresh()
                self.assertIsNone(self.runtime()["policy_entry_nonce"])
                self.assertEqual(self.sql("SELECT count(*) FROM adaptive_infrastructure"), [(1,)])
                self.sql("DELETE FROM adaptive_infrastructure")

    def test_old_guardian_epoch_and_barrier_are_independent_holds(self):
        owner = self.fresh()
        for field, value, reason in (("guardian_epoch", "old-epoch", "old_guardian_binding"),
                                     ("admission_barrier", "RECOVERY_HOLD", "unresolved_barrier")):
            with self.subTest(field=field):
                original = self.runtime()[field]
                self.sql("UPDATE adaptive_runtime SET " + field + "=?", (value,))
                with self.assertRaisesRegex(LifecycleError, reason):
                    owner.assert_fresh()
                self.assertIsNone(self.runtime()["policy_entry_nonce"])
                self.sql("UPDATE adaptive_runtime SET " + field + "=?", (original,))

    def test_binding_change_between_native_wait_and_recheck_refuses_acquisition(self):
        self.configure_mutex = lambda mutex: setattr(mutex, "on_enter", lambda:
            self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),)))
        owner = self.owner()
        with self.assertRaisesRegex(LifecycleError, "binding_changed") as caught:
            owner.acquire()
        self.assertIs(caught.exception._supervisor_startup, owner)
        with self.assertRaisesRegex(LifecycleError, "mutex_unverified"):
            owner.assert_held()

    def test_fresh_check_rejects_changed_persisted_binding(self):
        owner = self.fresh()
        self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            owner.assert_fresh()
        self.assertTrue(owner.policy_quarantined)

    def test_malformed_existing_binding_is_not_replaced(self):
        self.sql("UPDATE adaptive_runtime SET policy_binding_initialized=1,policy_instance_id='bad',policy_logon_id=?", (LOGON,))
        owner = self.owner()
        with self.assertRaisesRegex(Exception, "binding_invalid"):
            owner.acquire()
        self.assertEqual(self.runtime()["policy_instance_id"], "bad")
        self.assertFalse(self.mutexes)

    def test_partial_infrastructure_inventory_never_passes(self):
        owner = self.fresh()
        for pid in range(9001, 9034):
            self.sql("INSERT INTO adaptive_infrastructure VALUES('guardian',?,?,?,1)", (pid, str(10000 + pid), LOGON))
        with self.assertRaisesRegex(LifecycleError, "inventory_incomplete"):
            owner.assert_fresh()
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_infrastructure"), [(33,)])

    def test_other_logon_infrastructure_is_invalid_and_preserved(self):
        owner = self.fresh()
        self.add_infrastructure(owner, logon="S-1-5-5-1-9")
        with self.assertRaisesRegex(LifecycleError, "infrastructure_invalid"):
            owner.assert_fresh()
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_infrastructure"), [(1,)])

    def test_missing_or_malformed_empty_table_cannot_look_fresh(self):
        owner = self.fresh()
        self.sql("DROP TABLE adaptive_launch_fences")
        with self.assertRaisesRegex(LifecycleError, "inventory_unavailable"):
            owner.assert_fresh()
        self.sql("CREATE TABLE adaptive_launch_fences(execution_id TEXT)")
        with self.assertRaisesRegex(LifecycleError, "inventory_invalid"):
            owner.assert_fresh()

    def test_orphan_launch_request_refuses_even_without_execution(self):
        owner = self.fresh()
        self.sql("INSERT INTO adaptive_launch_requests VALUES(?,?,?,?,?,?)",
                 (str(uuid4()), "PrepareExecution", str(uuid4()), "a" * 64, "b" * 64, "old-guardian"))
        with self.assertRaisesRegex(LifecycleError, "old_scope_or_launch"):
            owner.assert_fresh()

    def test_orphan_manifest_and_incomplete_publication_refuse_without_read_or_delete(self):
        owner = self.fresh()
        for name in (str(uuid4()) + ".json", "." + str(uuid4()) + "." + uuid4().hex + ".tmp"):
            with self.subTest(name=name):
                target = self.directory / name
                target.write_text("malformed or partial evidence", encoding="utf-8")
                with self.assertRaisesRegex(LifecycleError, "old_manifest"):
                    owner.assert_fresh()
                self.assertTrue(target.exists())
                target.unlink()

    def test_unrelated_journal_files_are_allowed_but_truncated_directory_is_not(self):
        owner = self.fresh()
        (self.directory / "profile.json").write_text("{}", encoding="utf-8")
        owner.assert_fresh()
        for index in range(128):
            (self.directory / ("unrelated-" + str(index))).touch()
        with self.assertRaisesRegex(LifecycleError, "inventory_incomplete"):
            owner.assert_fresh()

    def test_assert_fresh_locked_borrows_policy_without_recursive_entry(self):
        owner = self.fresh()
        guard = self.store._policy.prepare(LOGON)
        with self.store._policy.hold(guard):
            self.assertEqual(owner.assert_fresh_locked()["policy_entry_nonce"], guard.nonce)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_unknown_wait_keeps_owner_and_never_closes_or_releases_numeric_handle(self):
        self.configure_mutex = lambda mutex: setattr(mutex, "wait_error", RuntimeError("ambiguous wait"))
        owner = self.owner()
        with self.assertRaises(RuntimeError) as caught:
            owner.acquire()
        self.assertIs(caught.exception._supervisor_startup, owner)
        for _ in range(2):
            with self.assertRaisesRegex(LifecycleError, "native_cleanup_unknown"):
                owner.close()
        self.assertEqual((self.mutexes[0].releases, self.mutexes[0].closes), (0, 0))

    def test_uncertain_release_is_never_retried_and_never_closes_mutex(self):
        owner = self.fresh()
        mutex = self.mutexes[0]
        mutex.release_error = RuntimeError("ambiguous release")
        with self.assertRaises(RuntimeError):
            owner.close()
        with self.assertRaisesRegex(LifecycleError, "native_cleanup_unknown"):
            owner.close()
        self.assertEqual((mutex.releases, mutex.closes), (1, 0))

    def test_known_close_failure_can_retry_close_without_reacquisition_or_rerelease(self):
        owner = self.fresh()
        mutex = self.mutexes[0]
        mutex.close_error = NativePolicyMutexError("policy_mutex_handle_close_failed", 5)
        with self.assertRaises(NativePolicyMutexError):
            owner.close()
        mutex.close_error = None
        owner.close()
        self.assertEqual((mutex.enters, mutex.releases, mutex.closes), (1, 1, 2))

    def test_ambiguous_close_never_reuses_numeric_handle(self):
        owner = self.fresh()
        mutex = self.mutexes[0]
        mutex.close_error = RuntimeError("close may have succeeded")
        with self.assertRaises(RuntimeError):
            owner.close()
        mutex.close_error = None
        with self.assertRaisesRegex(LifecycleError, "native_cleanup_unknown"):
            owner.close()
        self.assertEqual((mutex.enters, mutex.releases, mutex.closes), (1, 1, 1))

    def test_constructor_retained_cleanup_remains_reachable_and_quarantined(self):
        cleanup = object()
        failure = NativePolicyMutexError("policy_mutex_security_invalid")
        failure._policy_mutex_cleanup = (cleanup,)
        def factory(*args):
            raise failure
        owner = self.owner(mutex_factory=factory)
        with self.assertRaises(NativePolicyMutexError) as caught:
            owner.acquire()
        self.assertIs(caught.exception._supervisor_startup._construction_error._policy_mutex_cleanup[0], cleanup)
        with self.assertRaisesRegex(LifecycleError, "construction_cleanup_unknown"):
            owner.close()

    def test_database_failure_does_not_claim_fresh_or_clear_unknown_policy_outcome(self):
        owner = self.fresh()
        with patch("sentinel.adaptive.supervisor_startup.initialize_registry_locked", side_effect=sqlite3.OperationalError("fixture failure")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])

    def test_transient_sql_failure_retries_the_same_guard_and_never_prepares_a_second_nonce(self):
        owner = self.fresh()
        with patch("sentinel.adaptive.supervisor_startup.initialize_registry_locked", side_effect=sqlite3.OperationalError("fixture failure")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        retained = owner.policy_guard
        self.assertIsNotNone(retained)
        self.assertEqual(self.runtime()["policy_entry_nonce"], retained.nonce)
        self.assertTrue(owner.policy_pending)
        self.assertFalse(owner.policy_quarantined)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("must reuse original guard")):
            owner.assert_fresh()
        self.assertIsNone(owner.policy_guard)
        self.assertFalse(owner.policy_pending)
        self.assertTrue(owner.policy_result.complete)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_pending_policy_refuses_close_but_still_allows_the_original_retry(self):
        owner = self.fresh()
        with patch("sentinel.adaptive.supervisor_startup.initialize_registry_locked", side_effect=sqlite3.OperationalError("fixture failure")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        with self.assertRaisesRegex(LifecycleError, "policy_unsettled"):
            owner.close()
        self.assertTrue(owner.acquired)
        self.assertFalse(owner._closing)
        owner.assert_fresh()
        owner.close()
        self.assertFalse(owner.acquired)

    def test_changed_nonce_quarantines_pending_inspection_without_reentering_policy(self):
        owner = self.fresh()
        with patch("sentinel.adaptive.supervisor_startup.initialize_registry_locked", side_effect=sqlite3.OperationalError("fixture failure")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        retained = owner.policy_guard
        self.sql("UPDATE adaptive_runtime SET policy_entry_nonce=?", (str(uuid4()),))
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("changed nonce is no authority")):
            for _ in range(2):
                with self.assertRaisesRegex(LifecycleError, "policy_entry_changed"):
                    owner.assert_fresh()
        self.assertIs(owner.policy_guard, retained)
        self.assertTrue(owner.policy_quarantined)
        self.assertNotEqual(self.runtime()["policy_entry_nonce"], retained.nonce)

    def test_retry_rechecks_new_infrastructure_and_still_cold_holds(self):
        owner = self.fresh()
        with patch("sentinel.adaptive.supervisor_startup.initialize_registry_locked", side_effect=sqlite3.OperationalError("fixture failure")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        self.sql("INSERT INTO adaptive_infrastructure VALUES('guardian',9001,?,?,1)",
                 (str(CURRENT.created_filetime_100ns + 1), LOGON))
        with self.assertRaisesRegex(LifecycleError, "cold_adoption_unsupported"):
            owner.assert_fresh()
        self.assertFalse(owner.policy_pending)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_infrastructure"), [(1,)])

    def test_clear_commit_lost_ack_requires_new_inspection_instead_of_cached_fresh_snapshot(self):
        owner = self.fresh()
        clear = self.store._policy._clear
        def lost_ack(guard):
            clear(guard)
            raise sqlite3.OperationalError("fixture clear ACK lost")
        with patch.object(self.store._policy, "_clear", side_effect=lost_ack):
            with self.assertRaises(sqlite3.OperationalError):
                owner.assert_fresh()
        self.assertTrue(owner.policy_pending)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.sql("INSERT INTO adaptive_infrastructure VALUES('guardian',9001,?,?,1)",
                 (str(CURRENT.created_filetime_100ns + 1), LOGON))
        with self.assertRaisesRegex(LifecycleError, "policy_attempt_released_retry"):
            owner.assert_fresh()
        self.assertTrue(owner.policy_pending)
        self.assertIsNone(owner.policy_guard)
        with self.assertRaisesRegex(LifecycleError, "cold_adoption_unsupported"):
            owner.assert_fresh()
        self.assertFalse(owner.policy_pending)

    def test_unknown_policy_release_quarantines_and_does_not_retry_native_entry(self):
        owner = self.fresh()
        hold = self.policy.hold
        @contextmanager
        def uncertain(binding, *, timeout_ms):
            with hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise RuntimeError("fixture release outcome unknown")
        with patch.object(self.policy, "hold", side_effect=uncertain):
            with self.assertRaises(RuntimeError):
                owner.assert_fresh()
        self.assertTrue(owner.policy_quarantined)
        with patch.object(self.policy, "hold", side_effect=AssertionError("quarantined native entry")):
            with self.assertRaises(RuntimeError):
                owner.assert_fresh()
        with self.assertRaisesRegex(LifecycleError, "policy_unsettled"):
            owner.close()

    def test_bootstrap_clear_failure_retains_guard_and_retry_acquire_creates_singleton_once(self):
        owner = self.owner()
        with patch.object(self.store._policy, "_clear", side_effect=sqlite3.OperationalError("fixture bootstrap cleanup")):
            with self.assertRaises(sqlite3.OperationalError):
                owner.acquire()
        retained = owner.policy_guard
        self.assertIsNotNone(retained)
        self.assertTrue(owner.can_retry_acquire)
        self.assertTrue(owner.policy_pending)
        self.assertFalse(owner.acquired)
        self.assertFalse(self.mutexes)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("must reuse bootstrap guard")):
            self.assertIs(owner.retry_acquire(), owner)
        self.assertEqual(len(self.mutexes), 1)
        self.assertTrue(owner.acquired)
        self.assertFalse(owner.can_retry_acquire)
        self.assertFalse(owner.policy_pending)
        self.assertEqual(owner.binding, retained.binding)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        owner.assert_fresh()

    def test_bootstrap_lost_clear_ack_reconciles_same_binding_without_new_prepare(self):
        owner = self.owner()
        clear = self.store._policy._clear
        def lost_ack(guard):
            clear(guard)
            raise sqlite3.OperationalError("fixture bootstrap ACK lost")
        with patch.object(self.store._policy, "_clear", side_effect=lost_ack):
            with self.assertRaises(sqlite3.OperationalError):
                owner.acquire()
        binding = owner.policy_guard.binding
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertTrue(owner.can_retry_acquire)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no new bootstrap")):
            owner.retry_acquire()
        self.assertEqual(owner.binding, binding)
        self.assertTrue(owner.acquired)
        self.assertFalse(owner.policy_pending)
        self.assertEqual(len(self.mutexes), 1)

    def test_prepare_commit_lost_ack_has_no_returned_guard_and_cannot_reconstruct_it(self):
        owner = self.owner()
        prepare = self.store._policy.prepare
        prepared = []
        def lost_ack(logon):
            prepared.append(prepare(logon))
            raise sqlite3.OperationalError("fixture prepare ACK lost")
        with patch.object(self.store._policy, "prepare", side_effect=lost_ack):
            with self.assertRaisesRegex(LifecycleError, "policy_prepare_ownership_unknown"):
                owner.acquire()
        self.assertIsNone(owner.policy_guard)
        self.assertTrue(owner.policy_quarantined)
        self.assertTrue(owner.policy_pending)
        self.assertFalse(owner.can_retry_acquire)
        self.assertEqual(self.runtime()["policy_entry_nonce"], prepared[0].nonce)
        with self.assertRaisesRegex(LifecycleError, "acquire_retry_unavailable"):
            owner.retry_acquire()
        with self.assertRaisesRegex(LifecycleError, "policy_unsettled"):
            owner.close()
        self.assertFalse(self.mutexes)


if __name__ == "__main__":
    unittest.main()
