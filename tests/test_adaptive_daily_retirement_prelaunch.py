"""C2 cleanup after a real daily freeze, using original synthetic native owners.

Admission, generation, POLICY, freeze triggers, guardian, C2 archive and receipt
are real isolated production paths. No Job or operating-system process is made.
"""
from contextlib import closing
import json
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.daily_cohort import RetainedCohort
from sentinel.adaptive.daily_retirement_fence import OWNER_BINDING_FIELDS, install_freeze_locked
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_daily_cohort as cohort_fixture
from tests import test_adaptive_guardian_launch as launch_fixture
from tests import test_adaptive_prelaunch_receipt as receipt_fixture


class DailyRetirementPrelaunchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = receipt_fixture.PrelaunchReceiptTests(methodName="runTest")
        self.addCleanup(lambda: self.assertTrue(self.fixture.doCleanups(), "fixture cleanup failed"))
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        f = self.fixture
        root = f.directory.resolve()
        for override in (patch.object(generation, "daily_locations", return_value=(root, root)),
                         patch.object(generation, "verify_import_provenance", return_value=root)):
            override.start()
            self.addCleanup(override.stop)
        (root / "config.json").write_text(json.dumps({
            "admission_policy": "resource-v2", "local_allocatable_ram_gib": 58,
            "local_physical_headroom_gib": 4, "local_commit_headroom_gib": 4,
        }), encoding="utf-8")
        backend = cohort_fixture.Backend()
        backend.entries = [item for item in backend.entries if item.pid != 201]
        cohort = RetainedCohort.capture_current(backend=backend)
        self.addCleanup(cohort.close)
        manifest = generation.SourceManifest(tuple(generation.SourceEntry(name, "a" * 64, 0)
            for name in sorted(generation.REQUIRED_PATHS)))
        self.generation_owner = generation.DailyGenerationOwner(_token=generation._TOKEN,
            process=f.guardian, cohort=cohort, manifest=manifest,
            source_root=root, ledger_path=f.db.resolve())
        self.addCleanup(lambda: generation._LOCAL_GENERATIONS.pop(self.generation_owner.generation, None))
        policy = f.store._policy
        guard = policy.prepare(f.guardian.identity.logon_id)
        with policy.hold(guard):
            self.generation_owner.prepare_install(policy=policy, guard=guard)
            writer = sqlite3.connect(f.db, isolation_level=None)
            writer.row_factory = sqlite3.Row
            self.addCleanup(writer.close)
            writer.execute("BEGIN IMMEDIATE")
            self.generation_owner.install_locked(writer, policy=policy, guard=guard)
            writer.commit()
        self.generation_owner.settle_install_connection()
        with closing(sqlite3.connect(f.db)) as reader:
            self.generation_owner.acknowledge_install(conn=reader)

    def freeze(self, *, barrier="NONE"):
        policy = self.fixture.store._policy
        guard = policy.prepare(self.fixture.guardian.identity.logon_id)
        with policy.hold(guard):
            with self.fixture.store._transaction() as conn:
                row = generation.read_generation(conn)
                install_freeze_locked(conn, {key: row[key] for key in OWNER_BINDING_FIELDS},
                                      str(uuid4()), guard)
                conn.execute("UPDATE adaptive_runtime SET admission_barrier=? WHERE singleton=1", (barrier,))

    def delayed(self):
        case = self.fixture.admitted()
        self.mark_prepare_attempted(case)
        self.assertIsNone(self.fixture.row(case)["job_name"])
        self.freeze(barrier="RECOVERY_HOLD")
        self.fixture.owner.begin_drain()
        return case

    def mark_prepare_attempted(self, case):
        # GuardianLaunchTests.admitted models a distinct wrapper PID only in
        # its current-process scope. Reenter that same PID for this wrapper-side
        # operation; snapshot still observes the original retained process.
        with patch("sentinel.adaptive.admission.os.getpid",
                   return_value=case.snapshot.wrapper_identity.pid):
            case.admission.mark_prepare_attempted()

    def test_delayed_prepare_during_freeze_and_hold_retires_without_creating_job(self):
        f = self.fixture
        case = self.delayed()
        before = f.allocation(case)
        prepared = f.prepare(case)
        row = f.row(case)
        self.assertEqual(row["state"], "RESERVED")
        self.assertEqual((row["launch_sealed"], row["claim_consumed"], row["launch_in_flight"]), (1, 0, 0))
        self.assertEqual(row["state_revision"], case.prepare_request.expected_revision + 1)
        self.assertFalse(prepared.launch_authorized)
        self.assertEqual(f.jobs, [])
        self.assertEqual(f.allocation(case), before)
        entry = f.owner._pending[case.snapshot.execution_id]
        self.assertTrue(entry.retirement_sealed)
        self.assertFalse(entry.create_attempted)
        self.assertIsNone(entry.job)
        self.assertIsNone(entry.root)
        case.entry, case.wrapper_handle = entry, entry.wrapper._handle
        request = f.request(case)
        result = f.retire(case, request)
        self.assertEqual(result.state, "CANCELLED_BEFORE_START")
        self.assertIsNone(f.allocation(case))
        self.assertEqual(f.archive_count(case), 1)
        self.assertTrue(f.close_pending(case)["terminal"])
        receipt = f.read_receipt(case)
        self.assertEqual((receipt["job_disposition"], receipt["root_disposition"]),
                         ("never-created", "never-created"))
        self.assertEqual(set(receipt["closed_owners"]), {"wrapper", "mutex"})
        self.assertEqual(len(f.receipt_rows()), 1)
        self.assertNotIn(case.snapshot.execution_id, f.owner.retained_execution_ids)
        self.assertTrue(f.retire(case, request).duplicate)
        self.assertEqual(f.archive_count(case), 1)
        self.assertEqual(f.jobs, [])

    def test_ordinary_prepare_after_freeze_does_not_gain_retirement_exception(self):
        f = self.fixture
        case = f.admitted()
        self.mark_prepare_attempted(case)
        before = f.allocation(case)
        self.freeze()
        with self.assertRaisesRegex(LifecycleError, "daily_retirement_frozen"):
            f.prepare(case)
        row = f.row(case)
        self.assertEqual((row["state"], row["launch_sealed"], row["claim_consumed"]), ("RESERVED", 0, 0))
        self.assertIsNone(row["job_name"])
        self.assertEqual(f.allocation(case), before)
        self.assertEqual(f.jobs, [])

    def test_sealed_cleanup_scope_cannot_claim_or_create_user_work(self):
        f = self.fixture
        case = self.delayed()
        f.prepare(case)
        with self.assertRaises(LifecycleError):
            f.claim(case)
        self.assertEqual(f.row(case)["claim_consumed"], 0)
        self.assertEqual(f.row(case)["launch_in_flight"], 0)
        self.assertIsNone(f.row(case)["root_pid"])
        self.assertEqual(f.jobs, [])
        self.assertIsNotNone(f.allocation(case))

    def test_scope_sql_exception_cannot_bundle_demand_claim_root_or_unsealed_changes(self):
        f = self.fixture
        case = f.admitted()
        self.freeze()
        nonce = uuid4().hex
        base = {"job_name": f"Local\\ResourceSentinel.Job.{case.snapshot.execution_id}.{nonce}",
                "job_nonce": nonce, "guardian_epoch": launch_fixture.EPOCH,
                "launch_sealed": 1, "state_revision": f.row(case)["state_revision"] + 1}
        before = f.row(case)
        variants = ({"launch_sealed": 0}, {"state": "PREPARED"}, {"claim_consumed": 1},
                    {"launch_in_flight": 1}, {"root_pid": 99}, {"root_created_filetime_100ns": "123"},
                    {"requested_cpu_units": 2.0}, {"floor_commit_bytes": 9999999999},
                    {"claim_token_hash": "f" * 64}, {"job_nonce": "f" * 31},
                    {"job_name": "Local\\ResourceSentinel.Test.Job." + nonce},
                    {"guardian_epoch": None}, {"guardian_epoch": "bad\nvalue"})
        for change in variants:
            with self.subTest(fields=tuple(change)), f.store._transaction() as conn:
                updates = base | change
                with self.assertRaisesRegex(sqlite3.IntegrityError, "daily_retirement_frozen"):
                    conn.execute("UPDATE managed_executions SET " +
                        ",".join(name + "=?" for name in updates) + " WHERE execution_id=?",
                        (*updates.values(), case.snapshot.execution_id))
        self.assertEqual(f.row(case), before)
        self.assertEqual(f.jobs, [])


if __name__ == "__main__":
    unittest.main()
