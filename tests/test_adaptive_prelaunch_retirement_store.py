"""Portable C2 ledger/retirement evidence tests; no native acceptance claim."""
from contextlib import closing, contextmanager
import sqlite3
from types import SimpleNamespace
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import CpuControl, CpuControlMode, RecoveryManifest
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore, SchemaVersionError
from sentinel.adaptive.supervisor import GuardianSupervisor
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_guardian_launch as fixture


class PrelaunchRetirementStoreTests(unittest.TestCase):
    setUp = fixture.GuardianLaunchTests.setUp
    tearDown = fixture.GuardianLaunchTests.tearDown
    native_probe = fixture.GuardianLaunchTests.native_probe
    make_mutex = fixture.GuardianLaunchTests.make_mutex
    make_job = fixture.GuardianLaunchTests.make_job
    admitted = fixture.GuardianLaunchTests.admitted
    row = fixture.GuardianLaunchTests.row
    allocation = fixture.GuardianLaunchTests.allocation
    prepare = fixture.GuardianLaunchTests.prepare

    @contextmanager
    def policy_scope(self):
        guard = self.store._policy.prepare(fixture.LOGON)
        with self.store._policy.hold(guard):
            yield

    def sql(self, statement, values=()):
        with closing(sqlite3.connect(self.db)) as connection, connection:
            return connection.execute(statement, values).fetchall()

    def prepared(self):
        case = self.admitted()
        self.prepare(case)
        case.record = self.journal.read(case.snapshot.execution_id, creation_nonce=case.prepared.job_nonce)
        return case

    def proof(self, case, **changes):
        def evidence(operation, row, caller):
            return LifecycleEvidence(operation, row["execution_id"], row["state_revision"], "C2-fixture", caller,
                **dict(guardian_epoch=fixture.EPOCH, job_name=row["job_name"], job_nonce=row["job_nonce"],
                    active_process_count=0, process_ids=(), launch_sealed=True, user_code_started=False,
                    launch_failed=operation == "start_failed", durable_manifest=True,
                    original_cpu_disabled=True, current_cpu_disabled=True, recovery_manifest_settled=True,
                    retirement_manifest=case.record, total_process_count=0,
                    launch_fence_version=1 if row["claim_consumed"] else 0) | changes)
        self.store.evidence_provider = fixture_evidence_provider(evidence)

    def cancel(self, case):
        return self.store.cancel_before_start(case.snapshot.execution_id, caller=case.peer.identity,
            expected_revision=self.row(case)["state_revision"], now=fixture.NOW + 1)

    def fail(self, case):
        return self.store.mark_start_failed(case.snapshot.execution_id, caller=case.peer.identity,
            expected_revision=self.row(case)["state_revision"], now=fixture.NOW + 1)

    def fence(self, case):
        with self.policy_scope():
            return self.store.bind_launch_fence_locked(case.snapshot.execution_id,
                caller=case.peer.identity, expected_auth=case.auth, guardian_epoch=fixture.EPOCH)

    def claim(self, case):
        # The production guardian may itself bind this protocol; this fixture
        # binds first, then exercises the original store claim transition.
        self.fence(case)
        return self.store.claim_launch(case.snapshot.execution_id, caller=case.peer.identity,
            expected_revision=self.row(case)["state_revision"], claim_token=case.token,
            spec_hash=case.snapshot.spec_hash, guardian_epoch=fixture.EPOCH)

    def supervisor(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            runtime = connection.execute("SELECT * FROM adaptive_runtime").fetchone()
        recovery = SimpleNamespace(guardian_identity=fixture.GUARDIAN, guardian_epoch=fixture.EPOCH,
            binding=PolicyBinding(runtime["policy_instance_id"], runtime["policy_logon_id"]),
            journal=self.journal, retained_execution_ids=())
        return GuardianSupervisor(self.store, recovery)

    def test_cancel_receipt_and_exact_archive_retire_supervisor_scope(self):
        case = self.prepared()
        self.proof(case)
        result = self.cancel(case)
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertIsNone(self.allocation(case))
        self.store.assert_retained_terminal(result, case.record)
        self.assertEqual(self.sql("SELECT evidence_kind,total_process_count FROM adaptive_prelaunch_retirements"),
            [("never-associated", 0)])
        supervisor = self.supervisor()
        supervisor._refresh_inventory()
        self.assertEqual(supervisor._known, {})

    def test_start_failed_postclaim_requires_fence_and_retires(self):
        case = self.prepared()
        self.claim(case)
        self.proof(case)
        result = self.fail(case)
        self.assertEqual(result["state"], "START_FAILED")
        self.store.assert_retained_terminal(result, case.record)
        supervisor = self.supervisor()
        supervisor._refresh_inventory()
        self.assertEqual(supervisor._known, {})

    def test_missing_receipt_keeps_legacy_terminal_scope_as_obligation(self):
        case = self.prepared()
        self.proof(case, retirement_manifest=None)
        self.cancel(case)
        with self.assertRaisesRegex(LifecycleError, "prelaunch_retirement_unverified"):
            self.store.assert_retained_terminal(self.row(case), case.record)
        supervisor = self.supervisor()
        supervisor._refresh_inventory()
        self.assertEqual(supervisor._known, {case.snapshot.execution_id: case.record.creation_nonce})

    def test_lifetime_process_count_refuses_exited_before_bind_and_rolls_back_archive(self):
        case = self.prepared()
        self.claim(case)
        self.proof(case, total_process_count=1)
        with self.assertRaisesRegex(LifecycleError, "prelaunch_retirement_unverified"):
            self.fail(case)
        self.assertEqual(self.row(case)["state"], "LAUNCHING")
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(self.sql("SELECT count(*) FROM executions"), [(0,)])
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_prelaunch_retirements"), [(0,)])

    def test_postclaim_missing_fence_protocol_cannot_publish_receipt(self):
        case = self.prepared()
        self.claim(case)
        self.proof(case, launch_fence_version=0)
        with self.assertRaisesRegex(LifecycleError, "launch_fence_unverified"):
            self.fail(case)
        self.assertIsNotNone(self.allocation(case))

    def test_postclaim_cancel_stays_pending_without_receipt_or_release(self):
        case = self.prepared()
        self.claim(case)
        self.proof(case)
        result = self.cancel(case)
        self.assertEqual(result["reason"], "cancel_pending_reconciliation")
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_prelaunch_retirements"), [(0,)])
        self.assertIsNotNone(self.allocation(case))

    def test_nonrootless_or_applied_manifest_refuses_retirement(self):
        case = self.prepared()
        record = RecoveryManifest.create(**{name: getattr(case.record, name)
            for name in case.record.__dataclass_fields__ if name != "manifest_hash" and name != "last_applied"},
            last_applied=CpuControl(CpuControlMode.DISABLED, None))
        self.proof(case, retirement_manifest=record)
        with self.assertRaisesRegex(LifecycleError, "prelaunch_retirement_unverified"):
            self.cancel(case)
        self.assertIsNotNone(self.allocation(case))

    def test_receipt_tamper_and_duplicate_archive_refuse_terminal_proof(self):
        case = self.prepared()
        self.proof(case)
        result = self.cancel(case)
        self.sql("UPDATE adaptive_prelaunch_retirements SET manifest_hash=?", ("f" * 64,))
        with self.assertRaisesRegex(LifecycleError, "prelaunch_retirement_unverified"):
            self.store.assert_retained_terminal(result, case.record)
        self.sql("UPDATE adaptive_prelaunch_retirements SET manifest_hash=?", (case.record.manifest_hash,))
        columns = "reservation_id,request_key,owner_pid,repo,command_signature,resource_class,priority,cpu_units,ram_gib,io_slots,started_at,ended_at,outcome"
        self.sql(f"INSERT INTO executions ({columns}) SELECT {columns} FROM executions")
        with self.assertRaisesRegex(LifecycleError, "retained_terminal_unverified"):
            self.store.assert_retained_terminal(result, case.record)

    def test_prelaunch_terminal_cannot_clear_finished_barrier(self):
        case = self.prepared()
        self.proof(case)
        result = self.cancel(case)
        with self.policy_scope():
            with self.assertRaisesRegex(LifecycleError, "retained_terminal_unverified"):
                self.store.assert_finished_barrier_clearable(case.snapshot.execution_id,
                    caller=case.peer.identity, expected_revision=result["state_revision"], manifest=case.record)

    def test_launch_fence_is_immutable_and_read_only_check_rejects_stale_revision(self):
        case = self.prepared()
        self.assertFalse(self.fence(case))
        self.assertTrue(self.fence(case))
        row = self.row(case)
        self.store.assert_launch_fence(row)
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.assert_launch_fence(row | {"state_revision": row["state_revision"] + 1})
        self.sql("UPDATE adaptive_launch_fences SET spec_hash=?", ("f" * 64,))
        with self.assertRaisesRegex(LifecycleError, "launch_fence_unverified"):
            self.store.assert_launch_fence(row)

    def test_retirement_request_exact_replay_survives_terminal_but_changed_payload_does_not(self):
        case = self.prepared()
        request_id = str(uuid4())
        def record(request=request_id, digest="a" * 64):
            return self.store.record_retirement_request_locked(case.snapshot.execution_id,
                "CancelBeforeStart", request, digest, caller=case.peer.identity,
                expected_auth=case.auth, guardian_epoch=fixture.EPOCH)
        with self.policy_scope():
            self.assertFalse(record())
            self.assertTrue(record())
        self.proof(case)
        self.cancel(case)
        with self.policy_scope():
            self.assertTrue(record())
            with self.assertRaisesRegex(LifecycleError, "retirement_request_mismatch"):
                record(digest="b" * 64)
            with self.assertRaisesRegex(LifecycleError, "retirement_request_mismatch"):
                record(request=str(uuid4()))
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_retirement_requests"), [(1,)])

    def test_bad_additive_schema_is_not_silently_replaced(self):
        self.sql("ALTER TABLE adaptive_launch_fences ADD COLUMN unexpected TEXT")
        with self.assertRaisesRegex(SchemaVersionError, "prelaunch_schema_unsupported"):
            LifecycleStore(self.db, policy_provider=self.policy, existing_path=True)

    def test_request_precheck_is_read_only_and_mismatch_keeps_policy_usable(self):
        case = self.prepared()
        request_id = str(uuid4())
        args = (case.snapshot.execution_id, "CancelBeforeStart", request_id, "a" * 64)
        keywords = dict(caller=case.peer.identity, expected_auth=case.auth, guardian_epoch=fixture.EPOCH)
        with self.policy_scope():
            guard = self.store._policy.assert_held()
            before = self.sql("SELECT * FROM adaptive_runtime")
            self.assertFalse(self.store.check_retirement_request_locked(*args, **keywords))
            self.assertEqual(self.sql("SELECT * FROM adaptive_runtime"), before)
            self.assertEqual(self.sql("SELECT count(*) FROM adaptive_retirement_requests"), [(0,)])
            self.assertFalse(self.store.record_retirement_request_locked(*args, **keywords))
            self.assertTrue(self.store.check_retirement_request_locked(*args, **keywords))
            before = self.sql("SELECT * FROM adaptive_runtime")
            for changed in (args[:2] + (str(uuid4()), args[3]), args[:3] + ("b" * 64,)):
                with self.assertRaisesRegex(LifecycleError, "retirement_request_mismatch"):
                    self.store.check_retirement_request_locked(*changed, **keywords)
                self.assertIs(self.store._policy.assert_held(), guard)
                self.assertEqual(self.sql("SELECT * FROM adaptive_runtime"), before)
            self.assertTrue(self.store.check_retirement_request_locked(*args, **keywords))
        self.assertIsNone(self.sql("SELECT policy_entry_nonce FROM adaptive_runtime")[0][0])
        self.assertEqual(self.sql("SELECT count(*) FROM adaptive_retirement_requests"), [(1,)])


if __name__ == "__main__":
    unittest.main()
