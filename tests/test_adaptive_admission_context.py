"""Current-wrapper metadata tests; no Job creation or control writes."""
from dataclasses import FrozenInstanceError, asdict, replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive.admission import (
    ManagedAdmission, ManagedAdmissionUnavailable,
)
from sentinel.adaptive.contracts import (
    IdentityObservation, IdentityStatus, Priority, ProcessIdentity, ResourceDemand,
    Role, make_spec_hash,
)


IDENTITY = ProcessIdentity(os.getpid(), 134343072000000001, "S-1-5-5-100-200")
DEMAND = ResourceDemand(1.5, 512 * 1024 * 1024, 768 * 1024 * 1024, 1)
PAYLOAD = {
    "command": 'echo "private-launch-marker" & exit /b 7',
    "cwd": r"C:\private-cwd-marker\workspace",
    "repo_identifier": "resource-sentinel",
    "requested": DEMAND, "role": Role.BACKGROUND, "priority": Priority.P2,
}


class FakeCurrentProcess:
    def __init__(self, identity=IDENTITY):
        self.identity = identity
        self.observed = IdentityObservation(identity, IdentityStatus.ALIVE)
        self.observations = 0
        self.closes = 0

    def observe(self):
        self.observations += 1
        return self.observed

    def close(self):
        self.closes += 1


class ManagedAdmissionContextTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.db_path = Path(temporary.name) / "sentinel.db"
        self.db_path.touch()
        self.process = FakeCurrentProcess()
        current = patch("sentinel.adaptive.admission.VerifiedProcess.current",
                        return_value=self.process)
        self.current = current.start()
        self.addCleanup(current.stop)

    def create(self, **overrides):
        context = ManagedAdmission.current(**(PAYLOAD | overrides))
        self.addCleanup(context.close)
        return context

    def test_current_context_retains_exact_owner_and_resource_values(self):
        with self.create() as context:
            snapshot = context.snapshot()
            request = snapshot.request
            self.assertEqual(snapshot.wrapper_identity, IDENTITY)
            self.assertEqual(snapshot.logon_id, IDENTITY.logon_id)
            self.assertEqual(snapshot.requested, DEMAND)
            self.assertEqual(request.owner_pid, os.getpid())
            self.assertEqual(request.cpu_units, DEMAND.cpu_units)
            self.assertEqual(int(request.ram_gib * (1 << 30)), DEMAND.physical_bytes)
            self.assertEqual(request.commit_bytes, DEMAND.commit_bytes)
            self.assertEqual(request.io_slots, DEMAND.io_slots)
            self.assertEqual(request.tool_use_id, f"managed-v1:{snapshot.execution_id}")
            self.assertEqual(request.signature, snapshot.spec_hash[:20])
            self.assertNotEqual(request.spec_hash, snapshot.spec_hash)
            self.assertEqual(request.command, "")
            self.assertEqual(request.repo, PAYLOAD["repo_identifier"])
            self.assertEqual(request.priority, "P2")
        self.assertEqual(self.process.closes, 1)

    def test_retries_revalidate_same_handle_and_preserve_ids_and_hashes(self):
        context = self.create()
        initial_observations = self.process.observations
        first, second = context.snapshot(), context.snapshot()
        self.assertEqual(first, second)
        self.assertEqual(self.current.call_count, 1)
        self.assertEqual(self.process.observations, initial_observations + 2)

    def test_wrappers_share_unattributed_principal_not_execution_or_task(self):
        first, second = self.create().snapshot(), self.create().snapshot()
        self.assertEqual(first.principal_id, f"unattributed:{IDENTITY.logon_id}")
        self.assertEqual(first.principal_id, second.principal_id)
        self.assertEqual(first.session_id, second.session_id)
        self.assertIn(str(IDENTITY.created_filetime_100ns), first.session_id)
        self.assertNotEqual(first.execution_id, second.execution_id)
        self.assertNotEqual(first.task_id, second.task_id)
        self.assertNotEqual(first.binding_hash, second.binding_hash)

    def test_binding_hash_covers_immutable_attempt_metadata(self):
        key = b"k" * 32
        with patch("sentinel.adaptive.admission.secrets.token_bytes", return_value=key):
            snapshot = self.create().snapshot()
        self.assertEqual(snapshot.spec_hash, make_spec_hash(
            key=key, **PAYLOAD, parent_execution_id=None, caller=IDENTITY,
        ))
        binding = {
            "domain": "sentinel.managed-admission", "schema_version": 1,
            "spec_hash": snapshot.spec_hash, "execution_id": snapshot.execution_id,
            "task_id": snapshot.task_id, "session_id": snapshot.session_id,
            "principal_id": snapshot.principal_id,
            "claim_token_hash": snapshot.claim_token_hash,
            "wrapper_identity": IDENTITY.to_dict(), "requested": DEMAND.to_dict(),
            "role": Role.BACKGROUND.value, "priority": Priority.P2.value,
        }
        expected = hmac.new(key, json.dumps(
            binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("utf-8"), hashlib.sha256).hexdigest()
        self.assertEqual(snapshot.binding_hash, expected)
        self.assertNotEqual(snapshot.binding_hash, snapshot.spec_hash)

    def test_launch_claim_secret_is_stable_private_and_cleared_on_close(self):
        context = self.create()
        token = context.launch_claim_token()
        snapshot = context.snapshot()
        self.assertGreaterEqual(len(token), 32)
        self.assertEqual(token, context.launch_claim_token())
        self.assertEqual(hashlib.sha256(token.encode("ascii")).hexdigest(),
                         snapshot.claim_token_hash)
        self.assertNotIn(token, repr(context) + repr(snapshot) + json.dumps(asdict(snapshot)))
        context.close()
        self.assertIsNone(context._claim_token)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            context.launch_claim_token()

    def test_launch_payload_verification_accepts_original_payload(self):
        context = self.create()
        observations = self.process.observations
        self.assertIsNone(context.verify_launch_payload(
            command=PAYLOAD["command"], cwd=PAYLOAD["cwd"],
        ))
        self.assertEqual(self.process.observations, observations + 1)
        self.assertFalse(context._submitted)

    def test_launch_payload_verification_rejects_changed_or_invalid_payload(self):
        context = self.create()
        original = {"command": PAYLOAD["command"], "cwd": PAYLOAD["cwd"]}
        for changes in ({"command": PAYLOAD["command"] + " & echo changed"},
                        {"cwd": PAYLOAD["cwd"] + "-changed"},
                        {"command": "private-launch-marker\0"},
                        {"cwd": "relative-private-cwd-marker"}):
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    ManagedAdmissionUnavailable, "^launch_payload_mismatch$") as error:
                context.verify_launch_payload(**(original | changes))
            self.assertNotIn("private", str(error.exception))

    def test_launch_payload_verification_refuses_closed_unknown_or_foreign_identity(self):
        context = self.create()
        payload = {"command": PAYLOAD["command"], "cwd": PAYLOAD["cwd"]}
        self.process.observed = IdentityObservation(IDENTITY, IdentityStatus.UNKNOWN, "query_failed")
        with patch("sentinel.adaptive.admission.make_spec_hash") as hasher:
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
                context.verify_launch_payload(**payload)
            self.process.observed = IdentityObservation(IDENTITY, IdentityStatus.ALIVE)
            with patch("sentinel.adaptive.admission.os.getpid", return_value=IDENTITY.pid + 1):
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "not_current_process"):
                    context.verify_launch_payload(**payload)
            context.close()
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
                context.verify_launch_payload(**payload)
            hasher.assert_not_called()

    def test_private_key_stays_out_of_snapshot_and_repr_and_is_cleared_on_close(self):
        key = b"private-key-marker-32-bytes-long!!"
        with patch("sentinel.adaptive.admission.secrets.token_bytes", return_value=key):
            context = self.create()
        snapshot = context.snapshot()
        visible = repr(context) + repr(snapshot) + json.dumps(asdict(snapshot))
        self.assertNotIn(key.decode("ascii"), visible)
        self.assertNotIn(context.launch_claim_token(), visible)
        self.assertEqual(context._key, key)
        context.close()
        self.assertIsNone(context._key)
        self.assertIsNone(context._claim_token)

    def test_submission_flag_is_separate_from_snapshot_and_never_resets(self):
        context = self.create()
        inspected = context.snapshot()
        context.snapshot()
        first, is_first = context.begin_submission(db_path=self.db_path)
        self.assertEqual(first, inspected)
        self.assertTrue(is_first)
        second, is_second_first = context.begin_submission(db_path=self.db_path)
        self.assertEqual(second, inspected)
        self.assertFalse(is_second_first)

    def test_parallel_submissions_have_exactly_one_first_attempt(self):
        context = self.create()
        with ThreadPoolExecutor(max_workers=4) as pool:
            submissions = list(pool.map(lambda _: context.begin_submission(db_path=self.db_path), range(16)))
        self.assertEqual(sum(first for _, first in submissions), 1)
        self.assertTrue(all(snapshot == context.snapshot() for snapshot, _ in submissions))

    def test_failed_identity_check_does_not_consume_first_submission_or_expose_claim(self):
        context = self.create()
        with patch("sentinel.adaptive.admission.os.getpid", return_value=IDENTITY.pid + 1):
            for operation in (lambda: context.begin_submission(db_path=self.db_path), context.launch_claim_token):
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "not_current_process"):
                    operation()
        self.assertTrue(context.begin_submission(db_path=self.db_path)[1])
        context = self.create()
        self.process.observed = IdentityObservation(IDENTITY, IdentityStatus.UNKNOWN, "query_failed")
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
            context.begin_submission(db_path=self.db_path)
        self.process.observed = IdentityObservation(IDENTITY, IdentityStatus.ALIVE)
        self.assertTrue(context.begin_submission(db_path=self.db_path)[1])

    def test_closed_context_cannot_consume_submission(self):
        context = self.create()
        context.close()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            context.begin_submission(db_path=self.db_path)
        self.assertFalse(context._submitted)

    def test_submission_pins_canonical_ledger_before_outcome_and_rejects_other_ledger(self):
        context = self.create()
        other = self.db_path.with_name("other.db")
        other.touch()
        self.assertTrue(context.begin_submission(db_path=self.db_path)[1])
        self.assertEqual(context._admission_db_path, self.db_path.resolve())
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_ledger_mismatch"):
            context.begin_submission(db_path=other)
        self.assertFalse(context.begin_submission(db_path=self.db_path.parent / "." / self.db_path.name)[1])
        self.assertEqual(context._admission_db_path, self.db_path.resolve())

    def test_metadata_and_resource_request_are_frozen_and_payload_is_not_retained(self):
        context = self.create()
        snapshot = context.snapshot()
        with self.assertRaises(FrozenInstanceError):
            snapshot.task_id = "altered"
        with self.assertRaises(FrozenInstanceError):
            snapshot.request.command = "altered"
        with self.assertRaises(FrozenInstanceError):
            snapshot.requested.cpu_units = 0
        visible = repr(context.__dict__) + repr(snapshot) + json.dumps(asdict(snapshot))
        self.assertNotIn("private-launch-marker", visible)
        self.assertNotIn("private-cwd-marker", visible)
        self.assertNotIn("key", asdict(snapshot))

    def test_cannot_construct_context_from_claimed_metadata(self):
        with self.assertRaisesRegex(TypeError, "use_managed_admission_current"):
            ManagedAdmission()
        self.current.assert_not_called()
        for extra in ({"owner_pid": IDENTITY.pid}, {"principal_id": "chosen"},
                      {"session_id": "chosen"}, {"wrapper_identity": IDENTITY}):
            with self.subTest(extra=extra), self.assertRaises(TypeError):
                ManagedAdmission.current(**(PAYLOAD | extra))
        self.current.assert_not_called()

    def test_dead_or_unknown_identity_cannot_create_admission_context(self):
        for status in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            reason = "unavailable" if status is IdentityStatus.UNKNOWN else None
            self.process.observed = IdentityObservation(IDENTITY, status, reason)
            with self.subTest(status=status), self.assertRaisesRegex(
                    ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
                self.create()
        self.assertEqual(self.process.closes, 2)

    def test_snapshot_refuses_unknown_dead_or_changed_identity(self):
        context = self.create()
        for status in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            reason = "unavailable" if status is IdentityStatus.UNKNOWN else None
            self.process.observed = IdentityObservation(IDENTITY, status, reason)
            with self.subTest(status=status), self.assertRaisesRegex(
                    ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
                context.snapshot()
        self.process.observed = IdentityObservation(
            replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1),
            IdentityStatus.ALIVE,
        )
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_mismatch"):
            context.snapshot()

    def test_context_is_not_transferable_to_another_process(self):
        context = self.create()
        with patch("sentinel.adaptive.admission.os.getpid", return_value=IDENTITY.pid + 1):
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "not_current_process"):
                context.snapshot()
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "not_current_process"):
                self.create()

    def test_closing_invalidates_context_and_is_idempotent(self):
        context = self.create()
        context.close()
        context.close()
        self.assertEqual(self.process.closes, 1)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            context.snapshot()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            context.__enter__()

    def test_consumer_failure_closes_retained_handle(self):
        with self.assertRaisesRegex(RuntimeError, "consumer"):
            with self.create():
                raise RuntimeError("consumer")
        self.assertEqual(self.process.closes, 1)

    def test_invalid_payload_closes_handle_without_disclosing_payload(self):
        for overrides in ({"command": "private-launch-marker\0"},
                          {"cwd": "private-cwd-marker"},
                          {"repo_identifier": "private/repo"},
                          {"role": "background"}, {"priority": "P2"}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError) as error:
                self.create(**overrides)
            self.assertNotIn("private", str(error.exception))
        self.assertEqual(self.process.closes, 5)

    def test_inexact_resource_conversion_is_rejected_instead_of_rounding(self):
        for demand in (replace(DEMAND, physical_bytes=(1 << 53) + 1),
                       replace(DEMAND, cpu_units=(1 << 53) + 1)):
            with self.subTest(demand=demand), self.assertRaisesRegex(
                    ManagedAdmissionUnavailable, "resource_conversion_inexact"):
                self.create(requested=demand)
        self.assertEqual(self.process.closes, 2)

    def test_small_demands_do_not_silently_gain_legacy_default_values(self):
        for demand in (replace(DEMAND, physical_bytes=0),
                       replace(DEMAND, cpu_units=0)):
            with self.subTest(demand=demand), self.assertRaises(ValueError):
                self.create(requested=demand)


@unittest.skipUnless(os.name == "nt", "current-wrapper identity requires Windows")
class NativeManagedAdmissionSmokeTests(unittest.TestCase):
    def test_real_current_context_has_exact_native_identity_and_no_admission_side_effect(self):
        with ManagedAdmission.current(**PAYLOAD) as context:
            snapshot = context.snapshot()
            self.assertEqual(snapshot.wrapper_identity.pid, os.getpid())
            self.assertRegex(snapshot.logon_id, r"^S-1-5-5-[0-9]+-[0-9]+$")
            self.assertEqual(snapshot.request.owner_pid, os.getpid())
            self.assertEqual(snapshot.request.command, "")
            self.assertEqual(snapshot, context.snapshot())
            context.verify_launch_payload(command=PAYLOAD["command"], cwd=PAYLOAD["cwd"])


if __name__ == "__main__":
    unittest.main()
