"""Pure protocol tests for the scope fixture; no processes or native gates run."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tests.fixtures import adaptive_scope_workload as fixture


RUN_ID = "12345678-1234-4234-9234-123456789abc"
NONCE = "b" * 32
JOB_NONCE = "a" * 32
JOB = "Local\\ResourceSentinel.Job." + RUN_ID + "." + JOB_NONCE
IDENTITY = {"pid": 1200, "creation_time_100ns": 134_000_000_000_000_001}
PARENT = {"pid": 1000, "creation_time_100ns": 134_000_000_000_000_000}
NOW = 100_000_000_000


def arguments(*extra):
    return fixture.parser().parse_args([
        "--directory", str(Path.cwd()), "--run-id", RUN_ID, "--fixture-nonce", NONCE,
        "--scope", "unmanaged", "--deadline-ns", str(NOW + 10_000_000_000), *extra,
    ])


def ready(scope=None):
    scope = scope or fixture.Scope("managed", JOB, JOB_NONCE)
    return {
        "schema_version": 1, "status": "ready", "run_id": RUN_ID, "fixture_nonce": NONCE,
        "label": "child-1", "identity": dict(IDENTITY), "parent_identity": dict(PARENT),
        "deadline_ns": NOW + 10_000_000_000, "work_until_ns": NOW + 8_000_000_000,
        "scope": scope.mode, "job_name": scope.job_name, "job_nonce": scope.job_nonce,
        "priority_class": scope.priority_class, "scope_verified": True, "started_ns": NOW,
    }


def verify(record, scope=None):
    scope = scope or fixture.Scope("managed", JOB, JOB_NONCE)
    fixture.verify_child_ready(
        record, run_id=RUN_ID, nonce=NONCE, label="child-1", identity=IDENTITY,
        parent_identity=PARENT, deadline_ns=NOW + 10_000_000_000,
        work_until_ns=NOW + 8_000_000_000, scope=scope)


class BoundsTests(unittest.TestCase):
    def test_deadline_exact_maximum_is_permitted(self):
        self.assertEqual(fixture.validate_deadline(NOW + fixture.MAX_WORK_NS, NOW),
                         NOW + fixture.MAX_WORK_NS)

    def test_expired_or_extended_deadline_rejected(self):
        for deadline in (NOW - 1, NOW, NOW + fixture.MAX_WORK_NS + 1):
            with self.subTest(deadline=deadline), self.assertRaises(fixture.FixtureError):
                fixture.validate_deadline(deadline, NOW)

    def test_deadline_type_not_coerced(self):
        for deadline in (True, 10.5, "115", None, -1):
            with self.subTest(deadline=deadline), self.assertRaises(fixture.FixtureError):
                fixture.validate_deadline(deadline, NOW)

    def test_at_most_three_children_plus_root(self):
        self.assertEqual(fixture.parse_child_seconds("1,2,115"), (1.0, 2.0, 115.0))
        with self.assertRaisesRegex(fixture.FixtureError, "too_many_children"):
            fixture.parse_child_seconds("1,2,3,4")

    def test_no_children_supported(self):
        self.assertEqual(fixture.parse_child_seconds(""), ())

    def test_nonfinite_or_bad_child_duration_rejected(self):
        for value in ("nan", "inf", "-1", "0", "116", "1,", "1,x"):
            with self.subTest(value=value), self.assertRaises(fixture.FixtureError):
                fixture.parse_child_seconds(value)

    def test_duration_bool_is_not_numeric_duration(self):
        with self.assertRaises(fixture.FixtureError):
            fixture.duration(True)


class ScopeTests(unittest.TestCase):
    def test_managed_name_and_nonce_must_match(self):
        self.assertEqual(fixture.Scope("managed", JOB, JOB_NONCE).job_name, JOB)
        with self.assertRaisesRegex(fixture.FixtureError, "job_name_invalid"):
            fixture.Scope("managed", JOB, "c" * 32)

    def test_isolated_test_job_namespace_is_allowed(self):
        self.assertEqual(fixture.Scope("managed", "Local\\ResourceSentinel.Test.Job." + JOB_NONCE,
                                       JOB_NONCE).job_nonce, JOB_NONCE)

    def test_other_named_jobs_are_not_accepted(self):
        for name in ("OtherJob", "Global\\ResourceSentinel.Test.Job." + JOB_NONCE,
                     JOB + "extra", "Local\\ResourceSentinel.Job." + "0" * 36 + "." + JOB_NONCE):
            with self.subTest(name=name), self.assertRaises(fixture.FixtureError):
                fixture.Scope("managed", name, JOB_NONCE)

    def test_unmanaged_requires_explicit_no_job_and_normal(self):
        fixture.Scope("unmanaged")
        for kwargs in ({"job_name": JOB}, {"job_nonce": JOB_NONCE},
                       {"priority_class": fixture.BELOW_NORMAL}):
            with self.subTest(kwargs=kwargs), self.assertRaises(fixture.FixtureError):
                fixture.Scope("unmanaged", **kwargs)

    def test_only_normal_and_below_normal_are_expressible(self):
        for priority in (0x80, 0x100, 0x40, True, "32"):
            with self.subTest(priority=priority), self.assertRaises(fixture.FixtureError):
                fixture.Scope("managed", JOB, JOB_NONCE, priority)

    def test_no_job_query_unknown_is_not_no_job(self):
        with self.assertRaisesRegex(fixture.FixtureError, "scope_observation_unknown"):
            fixture.verify_context(fixture.Scope("unmanaged"), in_any_job=None,
                                   in_expected_job=None, priority_class=fixture.NORMAL)

    def test_foreign_job_denies_unmanaged_fixture(self):
        with self.assertRaisesRegex(fixture.FixtureError, "unmanaged_process_is_in_job"):
            fixture.verify_context(fixture.Scope("unmanaged"), in_any_job=True,
                                   in_expected_job=None, priority_class=fixture.NORMAL)

    def test_expected_specific_membership_required(self):
        for expected in (None, False, 1):
            with self.subTest(expected=expected), self.assertRaises(fixture.FixtureError):
                fixture.verify_context(fixture.Scope("managed", JOB, JOB_NONCE), in_any_job=True,
                                       in_expected_job=expected, priority_class=fixture.NORMAL)

    def test_priority_mismatch_denies_without_changing_it(self):
        with self.assertRaisesRegex(fixture.FixtureError, "priority_mismatch"):
            fixture.verify_context(fixture.Scope("managed", JOB, JOB_NONCE), in_any_job=True,
                                   in_expected_job=True, priority_class=fixture.BELOW_NORMAL)

    def test_positive_context_validation(self):
        fixture.verify_context(fixture.Scope("managed", JOB, JOB_NONCE), in_any_job=True,
                               in_expected_job=True, priority_class=fixture.NORMAL)
        fixture.verify_context(fixture.Scope("unmanaged"), in_any_job=False,
                               in_expected_job=None, priority_class=fixture.NORMAL)


class ProtocolTests(unittest.TestCase):
    def test_exact_original_identity_and_scope_match(self):
        verify(ready())

    def test_pid_reuse_birth_mismatch_rejected(self):
        value = ready()
        value["identity"]["creation_time_100ns"] += 1
        with self.assertRaisesRegex(fixture.FixtureError, "child_ready_identity_or_scope_mismatch"):
            verify(value)

    def test_another_process_cannot_supply_ready(self):
        value = ready()
        value["identity"]["pid"] += 1
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_wrong_parent_identity_rejected(self):
        value = ready()
        value["parent_identity"]["creation_time_100ns"] += 1
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_nonce_run_role_and_deadline_must_be_exact(self):
        for field, replacement in (("run_id", "22345678-1234-4234-9234-123456789abc"),
                                   ("fixture_nonce", "c" * 32), ("label", "child-2"),
                                   ("deadline_ns", NOW + 20_000_000_000),
                                   ("work_until_ns", NOW + 9_000_000_000)):
            value = ready()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(fixture.FixtureError):
                verify(value)

    def test_truthy_or_unknown_scope_flag_does_not_qualify(self):
        for flag in (1, "true", None, False):
            value = ready()
            value["scope_verified"] = flag
            with self.subTest(flag=flag), self.assertRaises(fixture.FixtureError):
                verify(value)

    def test_same_scope_name_different_nonce_refused(self):
        value = ready()
        value["job_nonce"] = "c" * 32
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_missing_field_and_wrong_schema_rejected(self):
        value = ready()
        del value["identity"]
        with self.assertRaises(fixture.FixtureError):
            verify(value)
        value = ready()
        value["schema_version"] = True
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_ready_after_absolute_deadline_rejected(self):
        value = ready()
        value["started_ns"] = value["deadline_ns"]
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_ready_after_own_work_deadline_rejected(self):
        value = ready()
        value["started_ns"] = value["work_until_ns"]
        with self.assertRaises(fixture.FixtureError):
            verify(value)

    def test_original_identity_input_itself_requires_filetime_integer(self):
        for identity in ({"pid": True, "creation_time_100ns": 123},
                         {"pid": 123, "creation_time_100ns": 1.5},
                         {"pid": 123}, {"pid": 123, "creation_time_100ns": 123, "extra": 1}):
            with self.subTest(identity=identity), self.assertRaises(fixture.FixtureError):
                fixture.validate_identity(identity)

    def test_retained_exception_preserves_same_owner(self):
        owner = object()
        failure = fixture.RetainedOwnerError("creation_custody_unresolved", owner)
        self.assertIs(failure.owner, owner)
        self.assertEqual(failure.reason, "creation_custody_unresolved")


class ArgumentTests(unittest.TestCase):
    def test_default_unmanaged_root_is_valid(self):
        self.assertEqual(fixture.validate_args(arguments()), fixture.Scope("unmanaged"))

    def test_child_requires_parent_filetime(self):
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_args(arguments("--role", "child", "--child-index", "1",
                                             "--work-until-ns", str(NOW + 5_000_000_000)))

    def test_child_cannot_spawn_more_children(self):
        with self.assertRaisesRegex(fixture.FixtureError, "child_role_invalid"):
            fixture.validate_args(arguments("--role", "child", "--child-index", "1", "--child-seconds", "1"))

    def test_root_cannot_supply_child_identity_arguments(self):
        with self.assertRaisesRegex(fixture.FixtureError, "root_has_child_only_arguments"):
            fixture.validate_args(arguments("--parent-pid", "123"))

    def test_nil_and_noncanonical_run_ids_rejected(self):
        for value in ("00000000-0000-0000-0000-000000000000", RUN_ID.upper(), "not-a-uuid"):
            with self.subTest(value=value), self.assertRaises(fixture.FixtureError):
                fixture.canonical_uuid(value)

    def test_fixture_nonce_is_required_and_strict(self):
        value = arguments()
        value.fixture_nonce = "not-a-nonce"
        with self.assertRaises(fixture.FixtureError):
            fixture.validate_args(value)


class RetainedSettlementTests(unittest.TestCase):
    """Injected ownership states only; this class never creates a native owner."""

    def owner(self, process_state="owned", thread_state="owned"):
        owner = object.__new__(fixture.NativeOwner)
        owner.creation_unknown = False
        owner.job_state = "owned"
        owner.children = [{"process_state": process_state, "thread_state": thread_state}]
        owner.alive = Mock(return_value=False)
        owner.cleanup = Mock()
        return owner

    def test_work_deadline_and_settlement_grace_are_distinct(self):
        self.assertEqual(fixture.MAX_WORK_NS, 115_000_000_000)
        self.assertEqual(fixture.SETTLEMENT_GRACE_NS, 2_000_000_000)

    def test_known_live_child_retains_original_owner(self):
        owner = self.owner()
        owner.alive.return_value = True
        self.assertFalse(owner.finish_known_children())
        owner.cleanup.assert_not_called()

    def test_positive_exit_allows_cleanup_without_managed_handoff(self):
        owner = self.owner()
        self.assertTrue(owner.finish_known_children())
        owner.cleanup.assert_called_once_with(allow_managed_handoff=False)

    def test_uncertain_close_is_never_queried_or_retried(self):
        for process, thread in (("close_unknown", "closed"), ("owned", "close_unknown")):
            owner = self.owner(process, thread)
            with self.subTest(process=process, thread=thread):
                self.assertFalse(owner.finish_known_children())
                owner.alive.assert_not_called()
                owner.cleanup.assert_not_called()

    def test_unknown_creation_never_becomes_empty(self):
        owner = self.owner()
        owner.creation_unknown = True
        self.assertFalse(owner.finish_known_children())
        owner.alive.assert_not_called()
        owner.cleanup.assert_not_called()

    def test_uncertain_job_close_does_not_repeat_the_call(self):
        owner = self.owner()
        owner.job_state = "close_unknown"
        self.assertFalse(owner.finish_known_children())
        owner.cleanup.assert_not_called()


class ReadyFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name).resolve() / "ready.json"

    def test_duplicate_identity_keys_rejected(self):
        self.path.write_text('{"identity":1,"identity":2}')
        with self.assertRaisesRegex(fixture.FixtureError, "child_ready_duplicate_key"):
            fixture.read_ready(self.path)

    def test_oversize_ready_rejected(self):
        self.path.write_text(" " * 8193)
        with self.assertRaisesRegex(fixture.FixtureError, "child_ready_too_large"):
            fixture.read_ready(self.path)

    def test_nonfinite_json_rejected(self):
        self.path.write_text('{"started_ns":NaN}')
        with self.assertRaisesRegex(fixture.FixtureError, "child_ready_nonfinite"):
            fixture.read_ready(self.path)

    def test_regular_ready_round_trip(self):
        self.path.write_text(json.dumps(ready()))
        verify(fixture.read_ready(self.path))

    def test_portable_cli_block_is_not_native_evidence(self):
        directory = self.path.parent
        with patch.object(fixture, "run", side_effect=fixture.FixtureError("windows_required")):
            code = fixture.main(["--directory", str(directory), "--run-id", RUN_ID,
                                 "--fixture-nonce", NONCE, "--scope", "unmanaged",
                                 "--deadline-ns", str(NOW + 10_000_000_000)])
        self.assertEqual(code, 2)
        result = json.loads((directory / "root.result.json").read_text())
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["root_exit_proves_scope_empty"])
        self.assertNotIn("completed_units", result)


if __name__ == "__main__":
    unittest.main()
