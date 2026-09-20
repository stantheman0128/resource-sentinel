"""L1 control-authority integration, never proof of native host readiness.

Admission, exemption revision/leases, policy ownership and the control slot use
real isolated SQLite stores. Native processes, Jobs and host readiness are
explicit fixtures; no daily data, control or global settings are used.
"""
from contextlib import closing, contextmanager
import sqlite3
import time
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import Mock, patch

from sentinel.adaptive.admission import ManagedAdmission
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand
from sentinel.adaptive.exemption_sync import ExemptionSyncError, bind_policy_locked, commit_grant_locked
from sentinel.adaptive.store import ControlSlotRejected, LifecycleError, LifecycleStore
from sentinel.exemptions import Exemptions
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, NOW, status
from tests import test_adaptive_execution_owner as owner_fixtures
from tests import test_adaptive_accounting as accounting_fixtures
from tests.windows import adaptive_execution
from tests.windows.adaptive_execution import S1ExecutionOwner, S1Runtime
from tests.windows.adaptive_control_authority import GrantRelation, NativeGrantScope, S1ControlAuthority


class SyntheticGrantScope:
    """Explicit relation fixture; it does not claim native identity evidence."""
    def __init__(self, result=GrantRelation.UNRELATED):
        self.result = result
        self.seen = []

    def relation(self, owner, lease):
        owner.assert_held()
        self.seen.append(dict(lease))
        return self.result


class S1ControlAuthorityTests(unittest.TestCase):
    # Reuse setup/helpers, never inherit another class's test methods.
    row = owner_fixtures.S1ExecutionOwnerTests.row
    manifest = owner_fixtures.S1ExecutionOwnerTests.manifest
    allocation = owner_fixtures.S1ExecutionOwnerTests.allocation
    policy_runtime = owner_fixtures.S1ExecutionOwnerTests.policy_runtime
    assert_floor_retained = owner_fixtures.S1ExecutionOwnerTests.assert_floor_retained
    launch = owner_fixtures.S1ExecutionOwnerTests.launch
    running = owner_fixtures.S1ExecutionOwnerTests.running
    make_empty = owner_fixtures.S1ExecutionOwnerTests.make_empty

    def setUp(self):
        owner_fixtures.S1ExecutionOwnerTests.setUp(self)
        self.host = self.authority
        self.exemptions = Exemptions(self.directory, chain=lambda pid: [(pid, float(pid))])
        self.scope = SyntheticGrantScope()
        self.control = S1ControlAuthority(data_dir=self.directory,
            exemptions=self.exemptions, host=self.host, scope=self.scope)
        self.owner.authority = self.control
        # Isolated fixture mode only: no daily production configuration changes.
        with self.store._transaction() as connection:
            connection.execute("UPDATE adaptive_runtime SET mode='canary' WHERE singleton=1")
        with self.owner.mutation_scope():
            bind_policy_locked(self.exemptions, self.store)

    def slot(self):
        with self.owner.mutation_scope():
            return self.store.query_control_slot_locked()

    def lease_record(self, pid=111, *, now=None, minutes=60):
        now = time.time() if now is None else now
        return dict(id=uuid.uuid4().hex, root_pid=pid, root_started=float(pid),
            created_at=now, expires_at=now + minutes * 60, reason="explicit isolated test grant",
            revoked_at=None, owner_metadata="{}")

    def grant(self, pid=111, **kwargs):
        record = self.lease_record(pid, **kwargs)
        with self.owner.mutation_scope():
            return commit_grant_locked(self.exemptions, record,
                lifecycle_store=self.store, now=record["created_at"])

    def saved_leases(self):
        with closing(sqlite3.connect(self.exemptions.path)) as connection:
            connection.row_factory = sqlite3.Row
            return [dict(row) for row in connection.execute("SELECT * FROM exemptions ORDER BY root_pid")]

    @contextmanager
    def capped_clock(self, *, on_sleep=None):
        clock = SimpleNamespace(now=time.monotonic(), waits=[])
        def sleep(seconds):
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, .25)
            self.assertIsNone(self.store._policy.current_guard())
            self.assertFalse(self.owner.mutex.acquired)
            clock.waits.append(seconds)
            clock.now += seconds
            if on_sleep is not None:
                on_sleep(clock)
        with patch("tests.windows.adaptive_execution.time.monotonic", side_effect=lambda: clock.now), \
                patch("tests.windows.adaptive_execution.time.sleep", side_effect=sleep):
            yield clock

    def second_owner(self, *, launch=False):
        demand = ResourceDemand(.5, 128 << 20, 128 << 20, 0)
        admission = ManagedAdmission.current(**(PAYLOAD | {"requested": demand}))
        self.addCleanup(admission.close)
        runtime = self.policy_runtime()
        self.assertEqual(runtime["mode"], "canary")
        # A canary admission requires a fresh fast frame. Supply an explicit
        # L1 telemetry fixture through the existing adapter seam, with this
        # real registry revision and no attribution deductions. Both managed
        # allocations retain their full floors; no production gate is changed.
        frame = accounting_fixtures.fast_frame(cpu=0, physical=16, commit=20,
                                               revision=runtime["registry_revision"])
        self.assertTrue(frame["fresh"])
        self.assertEqual(frame["source"], "fast")
        with patch("sentinel.coordinator.frame_from_status", return_value=frame):
            result = self.coordinator.admit_managed(admission, status(), config=CONFIG, now=NOW)
        self.assertTrue(result["allowed"], result)
        self.assertEqual(self.policy_runtime()["mode"], "canary")
        directory = self.directory / uuid.uuid4().hex
        directory.mkdir()
        store = LifecycleStore(self.coordinator.db_path, policy_provider=self.policy)
        owner = S1ExecutionOwner(admission=admission, store=store, authority=self.control,
            directory=directory, native=self.native)
        self.addCleanup(adaptive_execution._RETAINED_OWNERS.pop, owner.execution_id, None)
        owner.prepare()
        if launch:
            owner.launch_once("synthetic.exe", PAYLOAD["command"], cwd=PAYLOAD["cwd"],
                stdin_handle=11, stdout_handle=12, stderr_handle=13)
        return owner

    def test_held_slot_and_controlling_barrier_are_durable_before_native_set(self):
        self.running()
        def before_set(rate):
            self.owner.assert_held()
            slot = self.store.query_control_slot_locked()
            self.assertEqual(slot["slot_state"], "HELD")
            self.assertEqual(slot["execution_id"], self.execution_id)
            self.assertEqual(self.policy_runtime()["admission_barrier"], "CONTROLLING")
            self.assertIsNotNone(self.manifest().pending_intent)
        self.owner.job.set_observer = before_set
        with patch.object(self.host, "authorize_control", side_effect=AssertionError("raw host callback bypass")):
            self.owner.set_cpu_rate(2500)
        self.assertEqual(self.owner.job.control["rate_bp"], 2500)
        self.assertEqual(self.scope.seen, [])
        self.assert_floor_retained()

    def test_verified_restore_releases_slot_but_finalization_keeps_recovery_barrier(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        held = self.slot()
        self.owner.restore()
        restored = self.slot()
        self.assertEqual(restored["slot_id"], held["slot_id"])
        self.assertEqual(restored["slot_state"], "RESTORED")
        self.assertGreater(restored["slot_revision"], held["slot_revision"])
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.manifest().pending_intent)
        self.make_empty()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.assertIsNone(self.allocation())
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.owner.close()

    def test_second_job_cannot_replace_held_control_slot(self):
        self.running()
        second = self.second_owner(launch=True)
        self.owner.set_cpu_rate(2500)
        held = self.slot()
        with self.assertRaisesRegex(LifecycleError, "control_slot_occupied"):
            second.set_cpu_rate(1800)
        self.assertEqual(second.job.control["flags"], 0)
        second.restore()
        self.assertEqual(self.slot(), held)
        self.assertEqual(self.owner.job.control["rate_bp"], 2500)

    def test_controlling_barrier_blocks_another_prepared_job_launch(self):
        self.running()
        second = self.second_owner()
        before = self.native.launch_calls
        self.owner.set_cpu_rate(2500)
        with self.assertRaisesRegex(LifecycleError, "launch_barrier_active"):
            second.launch_once("synthetic.exe", PAYLOAD["command"], cwd=PAYLOAD["cwd"],
                stdin_handle=11, stdout_handle=12, stderr_handle=13)
        self.assertEqual(self.native.launch_calls, before)
        self.assertFalse(second.store.query(second.execution_id)["claim_consumed"])
        self.assertEqual(self.slot()["execution_id"], self.execution_id)

    def test_applicable_active_grant_denies_set_without_changing_lease(self):
        self.running()
        self.grant()
        before = self.saved_leases()
        self.scope.result = GrantRelation.APPLICABLE
        with self.assertRaisesRegex(LifecycleError, "execution_exempt"):
            self.owner.set_cpu_rate(2500)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertNotIn("job.set_cpu", self.events)
        self.assertEqual(self.saved_leases(), before)
        self.assertIsNone(self.slot())

    def test_unknown_active_grant_denies_set_without_becoming_unrelated(self):
        self.running()
        self.grant()
        self.scope.result = GrantRelation.UNKNOWN
        with self.assertRaisesRegex(LifecycleError, "exemption_scope_unknown"):
            self.owner.set_cpu_rate(2500)
        self.assertEqual(len(self.scope.seen), 1)
        self.assertNotIn("job.set_cpu", self.events)
        self.assertIsNone(self.slot())

    def test_dead_legacy_grant_still_reaches_native_unknown_scope_and_blocks(self):
        self.running()
        self.grant()
        self.exemptions.chain = lambda pid: []
        self.assertEqual(self.exemptions.rows(), [])
        self.control.scope = NativeGrantScope()
        with self.assertRaisesRegex(LifecycleError, "exemption_scope_unknown"):
            self.owner.set_cpu_rate(2500)
        self.assertNotIn("job.set_cpu", self.events)
        self.assertEqual(len(self.saved_leases()), 1)

    def test_new_grant_restores_existing_cap_before_rejecting_further_control(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        grant = self.grant()
        original_deadline = grant["expires_at"]
        self.scope.result = GrantRelation.APPLICABLE
        with self.assertRaisesRegex(LifecycleError, "execution_exempt"):
            self.owner.set_cpu_rate(1800)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertEqual(self.events.count("job.set_cpu"), 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual(self.saved_leases()[0]["expires_at"], original_deadline)
        self.assertIsNone(self.saved_leases()[0]["revoked_at"])

    def test_capped_wait_observes_new_grant_between_polls_and_invalidates_window(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        self.scope.result = GrantRelation.APPLICABLE
        granted = []
        def grant_while_sleeping(clock):
            if len(clock.waits) == 1:
                granted.append(self.grant())
        with self.capped_clock(on_sleep=grant_while_sleeping) as clock, \
                patch.object(self.owner, "set_cpu_rate", side_effect=AssertionError("poll performed another Set")):
            with self.assertRaisesRegex(LifecycleError, "execution_exempt"):
                self.owner.wait_capped(.75)
        self.assertEqual(clock.waits, [.25])
        self.assertEqual(len(granted), 1)
        self.assertEqual(self.events.count("job.set_cpu"), 1)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertIsNone(self.manifest().pending_intent)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        saved = self.saved_leases()[0]
        self.assertEqual(saved["id"], granted[0]["id"])
        self.assertEqual(saved["expires_at"], granted[0]["expires_at"])
        self.assertIsNone(saved["revoked_at"])
        self.assert_floor_retained()

    def test_capped_wait_grant_database_failure_restores_without_finishing_window(self):
        from sentinel.adaptive import exemption_sync
        self.running()
        self.owner.set_cpu_rate(2500)
        connect = exemption_sync._connect
        failed = False
        def break_read_after_sleep(clock):
            nonlocal failed
            failed = True
        def maybe_connect(*args, **kwargs):
            if failed:
                raise sqlite3.OperationalError("synthetic_grant_db_lost_during_window")
            return connect(*args, **kwargs)
        with self.capped_clock(on_sleep=break_read_after_sleep) as clock, \
                patch.object(exemption_sync, "_connect", side_effect=maybe_connect), \
                patch.object(self.owner, "set_cpu_rate", side_effect=AssertionError("poll performed another Set")):
            with self.assertRaisesRegex(ExemptionSyncError, "exemption_database_unavailable"):
                self.owner.wait_capped(.75)
        self.assertEqual(clock.waits, [.25])
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertEqual(self.events.count("job.set_cpu"), 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assert_floor_retained()

    def test_capped_wait_completes_full_window_without_renewal_or_new_set(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        original_slot = self.slot()
        original_manifest = self.manifest()
        with self.capped_clock() as clock, \
                patch.object(self.control, "observe_control", wraps=self.control.observe_control) as observe, \
                patch.object(self.owner, "set_cpu_rate", side_effect=AssertionError("poll performed another Set")):
            started = clock.now
            self.owner.wait_capped(.75)
        self.assertEqual(clock.waits, [.25, .25, .25])
        self.assertEqual(clock.now - started, .75)
        self.assertEqual(observe.call_count, 4)
        self.assertEqual(self.slot(), original_slot)
        self.assertEqual(self.manifest(), original_manifest)
        self.assertEqual(self.owner.job.control, {"flags": 5, "rate_bp": 2500})
        self.assertEqual(self.events.count("job.set_cpu"), 1)
        self.assertEqual(self.policy_runtime()["admission_barrier"], "CONTROLLING")
        self.owner.restore()

    def test_three_atomic_grants_and_repeat_keep_original_deadlines(self):
        self.running()
        now = time.time()
        first = self.grant(111, now=now, minutes=10)
        self.grant(222, now=now)
        self.grant(333, now=now)
        repeated = self.grant(111, now=now + 1, minutes=120)
        self.assertEqual(repeated["id"], first["id"])
        self.assertEqual(repeated["expires_at"], first["expires_at"])
        with self.assertRaisesRegex(ValueError, "exemption_limit_reached"):
            self.grant(444, now=now + 1)
        self.assertEqual(len(self.saved_leases()), 3)
        self.assertTrue(all(row["revoked_at"] is None for row in self.saved_leases()))

    def test_exemption_database_read_failure_withdraws_existing_cap(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        with patch("sentinel.adaptive.exemption_sync._connect",
                   side_effect=sqlite3.OperationalError("synthetic_grant_db_unavailable")):
            with self.assertRaisesRegex(ExemptionSyncError, "exemption_database_unavailable"):
                self.owner.set_cpu_rate(1800)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertEqual(self.events.count("job.set_cpu"), 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_failed_slot_begin_without_commit_restores_without_inventing_slot(self):
        self.running()
        with self.store._transaction() as connection:
            connection.execute("UPDATE adaptive_runtime SET mode='off' WHERE singleton=1")
        # Use the real begin transaction, decision rejection, rollback and
        # evidence cleanup. A generic exception cannot prove non-acquisition.
        with self.assertRaisesRegex(ControlSlotRejected, "control_mode_unavailable"):
            self.owner.set_cpu_rate(2500)
        episode = self.control._episodes[self.execution_id]
        self.assertTrue(episode["never_acquired"])
        self.assertFalse(episode["acquired"])
        self.assertNotIn("job.set_cpu", self.events)
        self.assertIsNone(self.slot())
        self.owner.restore()
        self.assertIsNone(self.slot())
        self.assertEqual(self.policy_runtime()["admission_barrier"], "NONE")
        self.make_empty()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")

    def test_generic_begin_failure_with_absent_slot_cannot_acknowledge_restore(self):
        self.running()
        with patch.object(self.store, "begin_control_slot_locked", side_effect=LifecycleError("synthetic_begin_unknown")):
            with self.assertRaisesRegex(LifecycleError, "synthetic_begin_unknown"):
                self.owner.set_cpu_rate(2500)
        episode = self.control._episodes[self.execution_id]
        self.assertFalse(episode["never_acquired"])
        self.assertFalse(episode["acquired"])
        self.assertIsNone(self.slot())
        with patch.object(self.host, "control_restored", wraps=self.host.control_restored) as acknowledgement:
            with self.assertRaisesRegex(LifecycleError, "control_slot_recovery_unverified"):
                self.owner.restore()
        acknowledgement.assert_not_called()
        self.assertFalse(episode["restored"])
        self.assert_floor_retained()

    def test_acquired_slot_disappearance_cannot_acknowledge_restore(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        episode = self.control._episodes[self.execution_id]
        self.assertTrue(episode["acquired"])
        # Isolated corruption: even a coherent conservative barrier does not
        # authorize inferring that an acknowledged acquisition never happened.
        with self.store._transaction() as connection:
            connection.execute("DELETE FROM adaptive_control_slot")
            connection.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD' WHERE singleton=1")
        with patch.object(self.host, "control_restored", wraps=self.host.control_restored) as acknowledgement:
            with self.assertRaisesRegex(LifecycleError, "control_slot_recovery_unverified"):
                self.owner.restore()
        acknowledgement.assert_not_called()
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertIsNone(self.manifest().pending_intent)
        self.assertFalse(episode["restored"])
        self.assertIsNone(self.slot())
        self.assert_floor_retained()
        self.make_empty()
        with self.assertRaisesRegex(LifecycleError, "case_control_recovery_unverified"):
            self.owner.finalize()
        self.assert_floor_retained()

    def test_acquired_slot_replaced_by_another_execution_remains_unacknowledged(self):
        self.running()
        second = self.second_owner(launch=True)
        self.owner.set_cpu_rate(2500)
        episode = self.control._episodes[self.execution_id]
        self.assertTrue(episode["acquired"])
        with self.store._transaction() as connection:
            connection.execute("""UPDATE adaptive_control_slot SET
                slot_id=?,execution_id=?,job_name=?,job_nonce=? WHERE singleton=1""",
                (str(uuid.uuid4()), second.execution_id, second.job_name, second.creation_nonce))
        foreign = self.slot()
        self.assertEqual(foreign["execution_id"], second.execution_id)
        with patch.object(self.host, "control_restored", wraps=self.host.control_restored) as acknowledgement:
            with self.assertRaisesRegex(LifecycleError, "control_slot_recovery_unverified"):
                self.owner.restore()
        acknowledgement.assert_not_called()
        self.assertEqual(self.slot(), foreign)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertFalse(episode["restored"])
        self.assert_floor_retained()
        self.make_empty()
        with self.assertRaisesRegex(LifecycleError, "case_control_recovery_unverified"):
            self.owner.finalize()
        self.assert_floor_retained()

    def test_lost_slot_commit_ack_restores_durable_slot_without_native_set(self):
        self.running()
        begin = self.store.begin_control_slot_locked
        def commit_then_lose_ack(*args, **kwargs):
            begin(*args, **kwargs)
            raise OSError("synthetic_slot_ack_lost")
        with patch.object(self.store, "begin_control_slot_locked", side_effect=commit_then_lose_ack):
            with self.assertRaisesRegex(OSError, "synthetic_slot_ack_lost"):
                self.owner.set_cpu_rate(2500)
        self.assertNotIn("job.set_cpu", self.events)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "CONTROLLING")
        self.owner.restore()
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.make_empty()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")

    def test_runtime_wraps_raw_host_and_does_not_delegate_control_authorization(self):
        runtime = S1Runtime(coordinator=self.coordinator, authority=self.host, native=self.native)
        self.assertIsInstance(runtime.authority, S1ControlAuthority)
        self.assertIs(runtime.authority.host, self.host)
        self.assertIsNot(runtime.authority, self.host)
        self.owner.authority = runtime.authority
        self.running()
        with patch.object(self.host, "authorize_control", side_effect=AssertionError("callback bypass")):
            self.owner.set_cpu_rate(2500)
        self.assertEqual(self.slot()["slot_state"], "HELD")


class NativeGrantScopeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.logon = "S-1-5-5-100-200"
        self.wrapper = ProcessIdentity(100, 134343072000000300, self.logon)
        self.grant_identity = ProcessIdentity(200, 134343072000000100, self.logon)
        self.nodes = {}
        self.opened = []
        self.owner = SimpleNamespace(caller=self.wrapper, job=object(),
            _grant_scope_handles=[], _retain=Mock(), observation_deadline=time.monotonic() + 120)
        self.owner.native = SimpleNamespace(ProcessHandle=SimpleNamespace(open=self.open))
        self.node(self.wrapper, parent=0)
        self.node(self.grant_identity, parent=0)
        self.lease = dict(root_pid=self.grant_identity.pid,
            root_created_filetime_100ns=str(self.grant_identity.created_filetime_100ns),
            root_logon_id=self.logon)

    def node(self, identity, *, parent=0, member=False, exited=False, close_error=False):
        self.nodes[identity.pid] = dict(identity=identity, parent=parent, member=member,
            exited=exited, close_error=close_error)

    def open(self, pid, birth=None):
        state = self.nodes[pid]
        if birth is not None and state["identity"].created_filetime_100ns != birth:
            raise OSError("synthetic_reused_pid")
        handle = SimpleNamespace(closed=False)
        handle.wait = lambda timeout: state["exited"]
        handle.full_identity = lambda **kwargs: state["identity"]
        handle.is_in_job = lambda job: state["member"]
        handle.parent_pid = lambda: state["parent"]
        def close():
            if state["close_error"]:
                raise OSError("synthetic_close_failed")
            handle.closed = True
        handle.close = close
        self.opened.append(handle)
        return handle

    def test_live_granted_job_member_protects_whole_job(self):
        self.nodes[200]["member"] = True
        self.assertIs(NativeGrantScope().relation(self.owner, self.lease), GrantRelation.APPLICABLE)
        self.assertTrue(all(handle.closed for handle in self.opened))

    def test_exact_live_wrapper_ancestor_protects_child_command(self):
        self.nodes[100]["parent"] = 200
        self.assertIs(NativeGrantScope().relation(self.owner, self.lease), GrantRelation.APPLICABLE)
        self.assertTrue(all(handle.closed for handle in self.opened))

    def test_verified_rooted_ancestry_and_nonmembership_can_prove_unrelated(self):
        self.assertIs(NativeGrantScope().relation(self.owner, self.lease), GrantRelation.UNRELATED)
        self.assertTrue(all(handle.closed for handle in self.opened))

    def test_missing_birth_dead_process_and_reused_parent_remain_unknown(self):
        legacy = {"root_pid": 200, "root_started": 10.0}
        self.assertIs(NativeGrantScope().relation(self.owner, legacy), GrantRelation.UNKNOWN)
        self.assertEqual(self.opened, [])
        self.nodes[200]["exited"] = True
        self.assertIs(NativeGrantScope().relation(self.owner, self.lease), GrantRelation.UNKNOWN)
        self.nodes[200]["exited"] = False
        newer = ProcessIdentity(300, self.wrapper.created_filetime_100ns + 1, self.logon)
        self.node(newer)
        self.nodes[100]["parent"] = 300
        self.assertIs(NativeGrantScope().relation(self.owner, self.lease), GrantRelation.UNKNOWN)

    def test_close_failure_invalidates_scope_proof_and_retains_exact_handle(self):
        self.nodes[200].update(member=True, close_error=True)
        with self.assertRaisesRegex(LifecycleError, "exemption_scope_cleanup_unverified"):
            NativeGrantScope().relation(self.owner, self.lease)
        self.assertEqual(self.owner._grant_scope_handles, self.opened)
        self.owner._retain.assert_called_once_with()
        self.assertFalse(self.opened[0].closed)


if __name__ == "__main__":
    unittest.main()
